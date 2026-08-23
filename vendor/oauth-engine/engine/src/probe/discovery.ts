/**
 * RFC 8414 / OpenID discovery (C-18, SPEC §1 `discovery` + §2 first bullet).
 *
 * "Fetch `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`.
 *  If present, most fields populate themselves and hand-configuration mostly disappears." (§2)
 *
 * The mapping is pure: given a metadata document, it derives the capability fields the
 * document actually justifies and NOTHING else. A field the document is silent on is left
 * for the engine's conservative default (it is not invented here). Every derived field gets
 * a receipt so `<name>.evidence.json` can show which metadata key produced it.
 */

import { evidenceBody, safeFetch } from './http.ts';
import type {
  ClientAuth,
  Dcr,
  DeviceFlow,
  Discovery,
  MeasuredProfile,
  Par,
  PkceMode,
  ProbeHttp,
  Receipt,
  Revocation,
  SenderConstraint,
} from './types.ts';

/** The two well-known suffixes, in the order §2 lists them. */
const WELL_KNOWN = [
  { suffix: '/.well-known/oauth-authorization-server', discovery: 'rfc8414' as Discovery },
  { suffix: '/.well-known/openid-configuration', discovery: 'oidc' as Discovery },
] as const;

export interface DiscoveryOutcome {
  /** Which document answered, or `'none'` when neither did. */
  discovery: Discovery;
  /** The parsed metadata document, when one was found. */
  document?: Record<string, unknown>;
  /** The URL that answered. */
  source_url?: string;
  /** Capability fields the document justifies. */
  fields: Partial<MeasuredProfile>;
  receipts: Receipt[];
}

/** Origin of a seed URL — discovery hangs the well-known suffix off the host, per RFC 8414. */
function originOf(target: string): string | undefined {
  try {
    return new URL(target).origin;
  } catch {
    return undefined;
  }
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out = value.filter((v): v is string => typeof v === 'string');
  return out.length > 0 ? out : undefined;
}

/** Map RFC 8414 `token_endpoint_auth_methods_supported` to our closed `client_auth` set. */
export function clientAuthFromMethods(methods: string[] | undefined): {
  value: ClientAuth;
  note: string;
} {
  if (methods === undefined) {
    return { value: 'unknown', note: 'metadata did not list token_endpoint_auth_methods_supported' };
  }
  const set = new Set(methods.map((m) => m.toLowerCase()));
  // A confidential-only server never lists `none`; a public server does. When both a public
  // and a secret method are offered, the live unauthenticated exchange (classify.ts) is the
  // tie-breaker — discovery alone reports what is *available*, not what is *required*.
  if (set.has('private_key_jwt')) return { value: 'private_key_jwt', note: 'private_key_jwt advertised (B2a-eligible)' };
  if (set.has('tls_client_auth') || set.has('self_signed_tls_client_auth')) {
    return { value: 'mtls', note: 'mTLS client authentication advertised' };
  }
  if (set.has('client_secret_post')) return { value: 'secret_post', note: 'client_secret_post advertised' };
  if (set.has('client_secret_basic')) return { value: 'secret_basic', note: 'client_secret_basic advertised' };
  if (set.has('none')) return { value: 'none', note: 'only `none` advertised — public client' };
  return { value: 'unknown', note: `unrecognized auth methods: ${methods.join(', ')}` };
}

/** Derive every capability field a metadata document supports. Pure — no I/O. */
export function mapMetadata(
  doc: Record<string, unknown>,
  discovery: Discovery,
  sourceUrl: string,
): { fields: Partial<MeasuredProfile>; receipts: Receipt[] } {
  const fields: Partial<MeasuredProfile> = {};
  const receipts: Receipt[] = [];
  const push = (field: string, value: Receipt['value'], note: string): void => {
    receipts.push({ field, value, method: 'rfc8414-discovery', request: { method: 'GET', url: sourceUrl }, note });
  };

  const authEndpoint = doc.authorization_endpoint;
  if (typeof authEndpoint === 'string') {
    fields.authorize_url = authEndpoint;
    push('authorize_url', authEndpoint, 'authorization_endpoint from metadata');
  }
  const tokenEndpoint = doc.token_endpoint;
  if (typeof tokenEndpoint === 'string') {
    fields.token_url = tokenEndpoint;
    push('token_url', tokenEndpoint, 'token_endpoint from metadata');
  }
  const revokeEndpoint = doc.revocation_endpoint;
  if (typeof revokeEndpoint === 'string') {
    fields.revoke_url = revokeEndpoint;
    fields.revocation = 'rfc7009' as Revocation;
    push('revoke_url', revokeEndpoint, 'revocation_endpoint present');
    push('revocation', 'rfc7009', 'revocation_endpoint present ⇒ RFC 7009');
  } else {
    fields.revocation = 'none' as Revocation;
    push('revocation', 'none', 'no revocation_endpoint in metadata');
  }

  // PKCE — code_challenge_methods_supported. Only S256 earns `S256`; anything weaker is `none`
  // (the profile's PkceMode is S256|none, and claiming S256 without proof would be a guess).
  const pkceMethods = stringArray(doc.code_challenge_methods_supported);
  if (pkceMethods !== undefined) {
    const s256 = pkceMethods.some((m) => m.toUpperCase() === 'S256');
    fields.pkce = (s256 ? 'S256' : 'none') as PkceMode;
    push('pkce', fields.pkce, `code_challenge_methods_supported = [${pkceMethods.join(', ')}]`);
  }

  const auth = clientAuthFromMethods(stringArray(doc.token_endpoint_auth_methods_supported));
  fields.client_auth = auth.value;
  push('client_auth', auth.value, auth.note);

  fields.discovery = discovery;
  push('discovery', discovery, `served at ${sourceUrl}`);

  // DCR — registration_endpoint ⇒ RFC 7591 (unlocks Custody Class C).
  if (typeof doc.registration_endpoint === 'string') {
    fields.dcr = 'rfc7591' as Dcr;
    push('dcr', 'rfc7591', 'registration_endpoint present ⇒ RFC 7591');
  } else {
    fields.dcr = 'none' as Dcr;
    push('dcr', 'none', 'no registration_endpoint in metadata');
  }

  // PAR — pushed_authorization_request_endpoint ⇒ RFC 9126.
  if (typeof doc.pushed_authorization_request_endpoint === 'string') {
    fields.par = 'rfc9126' as Par;
    push('par', 'rfc9126', 'pushed_authorization_request_endpoint present ⇒ RFC 9126');
  } else {
    fields.par = 'none' as Par;
    push('par', 'none', 'no pushed_authorization_request_endpoint in metadata');
  }

  // Sender constraint — DPoP alg list ⇒ dpop; mTLS auth ⇒ mtls; else bearer.
  const dpopAlgs = stringArray(doc.dpop_signing_alg_values_supported);
  const authMethods = new Set((stringArray(doc.token_endpoint_auth_methods_supported) ?? []).map((m) => m.toLowerCase()));
  let senderConstraint: SenderConstraint;
  let senderNote: string;
  if (dpopAlgs !== undefined) {
    senderConstraint = 'dpop';
    senderNote = `dpop_signing_alg_values_supported = [${dpopAlgs.join(', ')}]`;
  } else if (authMethods.has('tls_client_auth') || authMethods.has('self_signed_tls_client_auth')) {
    senderConstraint = 'mtls';
    senderNote = 'mTLS client auth advertised, no DPoP algs';
  } else {
    senderConstraint = 'bearer';
    senderNote = 'no DPoP or mTLS signalled — bearer';
  }
  fields.sender_constraint = senderConstraint;
  push('sender_constraint', senderConstraint, senderNote);

  // Device flow — endpoint or grant type ⇒ RFC 8628.
  const grantTypes = new Set((stringArray(doc.grant_types_supported) ?? []).map((g) => g.toLowerCase()));
  const deviceByEndpoint = typeof doc.device_authorization_endpoint === 'string';
  const deviceByGrant = grantTypes.has('urn:ietf:params:oauth:grant-type:device_code');
  const deviceFlow: DeviceFlow = deviceByEndpoint || deviceByGrant ? 'rfc8628' : 'none';
  fields.device_flow = deviceFlow;
  push(
    'device_flow',
    deviceFlow,
    deviceFlow === 'rfc8628'
      ? `device grant advertised (${deviceByEndpoint ? 'endpoint' : 'grant_type'})`
      : 'no device_authorization_endpoint or device_code grant',
  );

  return { fields, receipts };
}

/**
 * Fetch discovery for a seed URL. Tries the RFC 8414 document first, then OIDC. Returns
 * `discovery: 'none'` with an honest receipt when neither answers — the engine then treats
 * every downstream field as most-conservative (INV-CONFIG-5).
 */
export async function fetchDiscovery(target: string, http: ProbeHttp = {}): Promise<DiscoveryOutcome> {
  const origin = originOf(target);
  if (origin === undefined) {
    return {
      discovery: 'none',
      fields: { discovery: 'none' },
      receipts: [
        {
          field: 'discovery',
          value: 'none',
          method: 'rfc8414-discovery',
          note: `seed is not an absolute URL: ${target}`,
        },
      ],
    };
  }

  const attemptReceipts: Receipt[] = [];
  for (const wk of WELL_KNOWN) {
    const url = `${origin}${wk.suffix}`;
    const res = await safeFetch(url, { http });
    if (!res.ok) {
      attemptReceipts.push({
        field: 'discovery',
        value: 'unknown',
        method: 'rfc8414-discovery',
        request: { method: 'GET', url },
        note: `transport failure: ${res.error ?? 'unreachable'}`,
      });
      continue;
    }
    if (res.status === 200 && res.json !== undefined && res.json !== null && typeof res.json === 'object') {
      const doc = res.json as Record<string, unknown>;
      const mapped = mapMetadata(doc, wk.discovery, url);
      return { discovery: wk.discovery, document: doc, source_url: url, fields: mapped.fields, receipts: mapped.receipts };
    }
    attemptReceipts.push({
      field: 'discovery',
      value: 'unknown',
      method: 'rfc8414-discovery',
      request: { method: 'GET', url },
      response: { status: res.status, body: evidenceBody(res.text) },
      note: res.status === 200 ? 'document was not a JSON object' : `no metadata (HTTP ${res.status})`,
    });
  }

  return {
    discovery: 'none',
    fields: { discovery: 'none' },
    receipts: [
      ...attemptReceipts,
      {
        field: 'discovery',
        value: 'none',
        method: 'rfc8414-discovery',
        note: 'neither .well-known document was served — endpoints must be hand-configured',
      },
    ],
  };
}
