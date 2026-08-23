/**
 * The conformance probe orchestrator (C-1 / C-18 — SPEC Part 1 §2, §20 rung 2).
 *
 * `probe(input)` runs the safe measurement sequence and returns a {@link ProbeResult}: a
 * partial, measured `ProviderProfile` plus the receipt for every field. It is the machine
 * behind "the profile is measured, not asserted" (§2) and behind rung 2 of the wizard, where
 * a user pastes one URL and discovery + a doomed exchange + redirect probing answer most of
 * the questions so the wizard asks almost none (§20).
 *
 * Composition only: each sub-probe (discovery / classify / redirect / observe) is pure or
 * self-contained and separately tested. This file wires them, resolves conflicts with a
 * stated rule, defaults every undetermined SPEC §1 dimension to `unknown` (INV-CONFIG-5), and
 * derives the custody class from the measured `client_auth`.
 */

import { classifyClientAuth } from './classify.ts';
import { fetchDiscovery } from './discovery.ts';
import { probeRedirectTolerance } from './redirect.ts';
import { observeFirstRefresh, observeTokenResponse } from './observe.ts';
import type {
  CustodyClass,
  MeasuredProfile,
  ProbeEvidence,
  ProbeHttp,
  ProbeResult,
  Receipt,
  RelayMode,
} from './types.ts';

export interface ProbeInput {
  /** Stable key — the vault account name and getToken() key. */
  name: string;
  display_name?: string;
  /** Seed URL: a documentation URL, the issuer origin, or the authorize endpoint (rung 2). */
  target: string;
  /** Public client id, if the author has registered one. Sharpens classification. Not a secret. */
  client_id?: string;
  /** Explicit endpoints, used when discovery does not serve them. */
  authorize_url?: string;
  token_url?: string;
  /** Scopes the connect will request — enables `scope_grant` classification. */
  scopes?: string[];
  /** A captured token response from a real connect, for shape/expiry/scope observation. */
  tokenResponse?: unknown;
  /** The refresh token originally issued, plus the first refresh's response, for rotation. */
  originalRefreshToken?: string;
  firstRefreshResponse?: unknown;
  /** Set false to skip network authorize probing (redirect tolerance). Default: probe it. */
  probeRedirect?: boolean;
  http?: ProbeHttp;
}

/** The SPEC §1 capability dimensions that must always resolve to a value (unknown if not measured). */
const CONSERVATIVE_DEFAULTS: Partial<MeasuredProfile> = {
  client_auth: 'unknown',
  discovery: 'unknown',
  dcr: 'unknown',
  par: 'unknown',
  sender_constraint: 'unknown',
  device_flow: 'unknown',
  scope_grant: 'unknown',
  revocation: 'unknown',
};

/** Derive the custody rung from the measured profile (§4, §5b) — never hand-authored. */
export function deriveCustody(fields: Partial<MeasuredProfile>): {
  custody_class: CustodyClass;
  relay_mode: RelayMode;
  receipt: Receipt;
} {
  const auth = fields.client_auth ?? 'unknown';
  const pkce = fields.pkce;
  let custody_class: CustodyClass;
  let relay_mode: RelayMode = 'none';
  let note: string;

  if (auth === 'none') {
    custody_class = pkce === 'S256' ? 'A' : 'A';
    note =
      pkce === 'S256'
        ? 'client_auth none + pkce S256 ⇒ Class A (public, fully on-device)'
        : 'client_auth none ⇒ Class A (public); pkce not confirmed S256 — engine treats missing PKCE conservatively';
  } else if (auth === 'private_key_jwt') {
    custody_class = 'B2a';
    relay_mode = 'assertion_signing';
    note = 'private_key_jwt ⇒ Class B2a (relay signs an assertion, never sees a token)';
  } else if (auth === 'secret_post' || auth === 'secret_basic') {
    custody_class = 'B1';
    note = `${auth} ⇒ confidential; default rung B1 (user brings own secret, on-device). B2b relay is the alternative`;
  } else if (auth === 'mtls') {
    custody_class = 'unknown';
    note = 'mTLS sender-constrained client — custody rung out of the current A/B1/B2/C ladder; needs a cert path';
  } else if (fields.dcr === 'rfc7591') {
    custody_class = 'C';
    note = 'client_auth undetermined but RFC 7591 DCR available ⇒ Class C (self-registered, credentials on device)';
  } else {
    custody_class = 'unknown';
    note = 'client_auth undetermined and no DCR ⇒ custody unknown (most-conservative)';
  }

  return {
    custody_class,
    relay_mode,
    receipt: { field: 'custody_class', value: custody_class, method: 'derived', note },
  };
}

export async function probe(input: ProbeInput): Promise<ProbeResult> {
  const http = input.http ?? {};
  const receipts: Receipt[] = [];
  const notes: Record<string, string> = {};
  const fields: Partial<MeasuredProfile> = {};

  // 1) Discovery (C-18).
  const discovery = await fetchDiscovery(input.target, http);
  Object.assign(fields, discovery.fields);
  receipts.push(...discovery.receipts);

  const tokenUrl = input.token_url ?? discovery.fields.token_url;
  const authorizeUrl = input.authorize_url ?? discovery.fields.authorize_url;
  if (input.token_url !== undefined) fields.token_url = input.token_url;
  if (input.authorize_url !== undefined) fields.authorize_url = input.authorize_url;

  // 2) Client-auth classification via the doomed unauthenticated exchange (§2).
  if (tokenUrl !== undefined) {
    const confidentialMethod =
      discovery.fields.client_auth !== undefined &&
      discovery.fields.client_auth !== 'none' &&
      discovery.fields.client_auth !== 'unknown'
        ? discovery.fields.client_auth
        : undefined;
    const classification = await classifyClientAuth(tokenUrl, input.client_id, http, confidentialMethod);
    receipts.push(classification.receipt);
    // Rule: a definitive LIVE result wins over discovery's "available methods" reading; an
    // `unknown` live result defers to whatever discovery could name.
    if (classification.value !== 'unknown') {
      fields.client_auth = classification.value;
    } else if (discovery.fields.client_auth !== undefined) {
      fields.client_auth = discovery.fields.client_auth;
    }
  } else {
    receipts.push({
      field: 'client_auth',
      value: 'unknown',
      method: 'unauthenticated-token-exchange',
      note: 'no token endpoint from discovery or input — cannot classify client authentication',
    });
  }

  // 3) Redirect / host tolerance (§2, §7).
  if (authorizeUrl !== undefined && input.probeRedirect !== false) {
    const redirect = await probeRedirectTolerance(authorizeUrl, input.client_id, http);
    receipts.push(...redirect.receipts);
    if (redirect.redirect_host !== undefined) fields.redirect_host = redirect.redirect_host;
    notes.redirect_dimension = `${redirect.redirect} (tolerated hosts: ${redirect.tolerated_hosts.join(', ') || 'none determined'})`;
  } else if (input.probeRedirect !== false) {
    receipts.push({
      field: 'redirect_host',
      value: 'unknown',
      method: 'authorize-redirect-tolerance',
      note: 'no authorize endpoint to probe redirect tolerance against',
    });
  }

  // 4) Connect-time observations (§2) — only when a real response was captured.
  if (input.tokenResponse !== undefined) {
    const shape = observeTokenResponse(input.tokenResponse, input.scopes);
    Object.assign(fields, shape.fields);
    receipts.push(...shape.receipts);
    if (shape.granted_scopes !== undefined) notes.granted_scopes = shape.granted_scopes.join(' ');
  }
  if (input.firstRefreshResponse !== undefined) {
    const rotation = observeFirstRefresh(input.originalRefreshToken, input.firstRefreshResponse);
    Object.assign(fields, rotation.fields);
    receipts.push(rotation.receipt);
  }

  // 5) Every undetermined SPEC §1 dimension resolves to `unknown` (INV-CONFIG-5).
  for (const [key, value] of Object.entries(CONSERVATIVE_DEFAULTS) as [keyof MeasuredProfile, string][]) {
    if (fields[key] === undefined) {
      (fields as Record<string, unknown>)[key] = value;
      receipts.push({
        field: String(key),
        value: value as Receipt['value'],
        method: 'conservative-default',
        note: 'not determinable by this probe run — defaulted to the most-conservative value',
      });
    }
  }

  // 6) Derive custody (§4, §5b).
  const custody = deriveCustody(fields);
  fields.custody_class = custody.custody_class;
  fields.relay_mode = custody.relay_mode;
  receipts.push(custody.receipt);

  const evidence: ProbeEvidence = {
    provider: input.name,
    probed_at: new Date().toISOString(),
    target: input.target,
    receipts,
  };

  const profile: ProbeResult['profile'] = {
    $schema: '../provider.schema.json',
    schema_version: 1,
    name: input.name,
    display_name: input.display_name ?? input.name,
    ...fields,
    ...(Object.keys(notes).length > 0 ? { _notes: notes } : {}),
  };

  return { profile, evidence };
}
