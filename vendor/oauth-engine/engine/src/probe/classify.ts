/**
 * Client-authentication classification (C-1, SPEC §2 third bullet — "the distinction is the
 * whole ballgame and it is machine-detectable").
 *
 *   "Attempt a token exchange without client authentication and classify the failure
 *    precisely. A `401 invalid_client` means confidential; a `400 invalid_grant` means the
 *    auth was fine and something else was wrong."
 *
 * The request is deliberately safe and deliberately doomed: a syntactically valid
 * `authorization_code` grant carrying a throwaway code that no provider will ever honor. We
 * are not trying to get a token; we are reading WHICH failure the provider chooses, because
 * the failure names the custody class.
 *
 * When a public (non-secret) `client_id` is supplied — it is not a credential — the signal is
 * crisp: a public provider accepts the client and rejects only the bad code (`invalid_grant`),
 * while a confidential provider rejects the missing secret first (`invalid_client`). With no
 * client_id at all the signal is weaker and the probe says so: `invalid_client` becomes
 * `unknown` (INV-CONFIG-5) rather than a guessed confidential.
 */

import { evidenceBody, safeFetch } from './http.ts';
import type { ClientAuth, ProbeHttp, Receipt } from './types.ts';

/** A code no provider issued. Long enough to look real, meaningless enough to be safe. */
const THROWAWAY_CODE = 'handshake-probe-invalid-code-000000';
/** A syntactically valid loopback redirect that will not match any real registration. */
const THROWAWAY_REDIRECT = 'http://127.0.0.1:1/callback';

export interface ClientAuthClassification {
  /** `'none'` = public, `'unknown'` = confidential-or-undeterminable (conservative). */
  value: ClientAuth;
  /** `true` when the provider clearly requires a secret at the token endpoint. */
  confidential: boolean;
  receipt: Receipt;
}

function errorCode(json: unknown): string | undefined {
  if (json === null || typeof json !== 'object') return undefined;
  const e = (json as Record<string, unknown>).error;
  return typeof e === 'string' ? e.toLowerCase() : undefined;
}

/**
 * Classify by attempting an unauthenticated exchange.
 *
 * @param tokenUrl   the provider's token endpoint (from config or discovery).
 * @param clientId   the PUBLIC client id, if the author has one. Sharpens the signal; optional.
 * @param confidentialMethod  when discovery already named the secret method (`secret_post`,
 *                            `secret_basic`, `private_key_jwt`, `mtls`), it is reported instead
 *                            of a bare confidential `unknown`.
 */
export async function classifyClientAuth(
  tokenUrl: string,
  clientId: string | undefined,
  http: ProbeHttp = {},
  confidentialMethod?: ClientAuth,
): Promise<ClientAuthClassification> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: THROWAWAY_CODE,
    redirect_uri: THROWAWAY_REDIRECT,
  });
  if (clientId !== undefined && clientId !== '') body.set('client_id', clientId);

  const res = await safeFetch(tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    http,
  });

  const request = { method: 'POST', url: tokenUrl, body: body.toString() };

  if (!res.ok) {
    return {
      value: 'unknown',
      confidential: false,
      receipt: {
        field: 'client_auth',
        value: 'unknown',
        method: 'unauthenticated-token-exchange',
        request,
        note: `transport failure: ${res.error ?? 'unreachable'}`,
      },
    };
  }

  const code = errorCode(res.json);
  const response = { status: res.status, body: evidenceBody(res.text) };
  const named = (value: ClientAuth, confidential: boolean, note: string): ClientAuthClassification => ({
    value,
    confidential,
    receipt: { field: 'client_auth', value, method: 'unauthenticated-token-exchange', request, response, note },
  });

  // The error code is authoritative over the HTTP status — some providers return 400 with
  // `invalid_client`, others 401 with it, and the RFC 6749 §5.2 name is the reliable signal.
  if (code === 'invalid_client' || res.status === 401) {
    const value = confidentialMethod ?? 'unknown';
    if (clientId === undefined || clientId === '') {
      // No client_id was sent, so `invalid_client` cannot be distinguished from "you forgot
      // your client_id" on a public provider. Conservative: unknown, with the reason.
      return named(
        confidentialMethod ?? 'unknown',
        confidentialMethod !== undefined,
        `invalid_client with no client_id supplied — confidential vs missing-id is ambiguous;${confidentialMethod ? ` discovery names ${confidentialMethod}` : ' rerun with the public client_id to disambiguate'}`,
      );
    }
    return named(
      value,
      true,
      `client rejected without a secret (${code ?? `HTTP ${res.status}`}) ⇒ confidential${confidentialMethod ? ` (${confidentialMethod} per discovery)` : ' (method undetermined — supply discovery to name it)'}`,
    );
  }

  // invalid_grant / invalid_request / invalid_code / unsupported... — the client auth was
  // NOT the objection, so no secret is required at the token endpoint: a public client.
  if (
    code === 'invalid_grant' ||
    code === 'invalid_code' ||
    code === 'invalid_request' ||
    res.status === 400
  ) {
    return named(
      'none',
      false,
      `client accepted, only the throwaway code was rejected (${code ?? `HTTP ${res.status}`}) ⇒ public client, no secret required`,
    );
  }

  return named(
    'unknown',
    false,
    `unclassifiable response (HTTP ${res.status}${code ? `, error=${code}` : ''}) — treated as most-conservative`,
  );
}
