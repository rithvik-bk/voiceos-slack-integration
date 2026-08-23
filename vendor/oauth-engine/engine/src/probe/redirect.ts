/**
 * Redirect / loopback-host tolerance (C-1, SPEC §2 fourth bullet, §7).
 *
 *   "Probe redirect tolerance across a fixed port, a random high port, and each loopback
 *    host literal."
 *
 * The probe issues a real authorization request per candidate redirect and reads the
 * provider's *immediate* reaction — never following through to consent. The only reliable,
 * safe signal is an explicit redirect REJECTION (`redirect_uri_mismatch`, `invalid_redirect`,
 * a bounce whose Location carries a redirect error). A provider that instead bounces to its
 * own login page has, as far as is safely measurable, accepted the redirect.
 *
 * Honesty rule (INV-CONFIG-5): where the signal is drowned out — most often because no valid
 * `client_id` was supplied and the provider rejects the client before it ever inspects the
 * redirect — the outcome is `'unknown'`, not a guess. `localhost`, `127.0.0.1` and `[::1]`
 * are NOT interchangeable in provider allowlists (config.ts C-ZM-24), so each is probed
 * separately and the tolerated set is recorded, not collapsed.
 */

import { CALLBACK_PATH } from '../config.ts';
import { evidenceBody, safeFetch } from './http.ts';
import type { ProbeHttp, Receipt } from './types.ts';

/** Host literals providers disagree on. Each probed independently. */
export const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'] as const;

/** Substrings that mean "the redirect_uri itself was refused". */
const REJECT_PATTERNS = [
  'redirect_uri_mismatch',
  'invalid_redirect',
  'bad_redirect',
  'redirect uri',
  'redirect_uri is not',
  'redirect_uri did not match',
  'unregistered',
] as const;

export type RedirectOutcome = 'tolerated' | 'rejected' | 'unknown';

export interface RedirectProbe {
  host: string;
  port: number;
  kind: 'fixed' | 'random';
  redirect_uri: string;
  outcome: RedirectOutcome;
  receipt: Receipt;
}

export interface RedirectToleranceResult {
  probes: RedirectProbe[];
  /** Host literals with at least one tolerated redirect, in probe order. */
  tolerated_hosts: string[];
  /** SPEC §7 redirect dimension — no typed profile field yet, so surfaced via notes/evidence. */
  redirect: 'loopback_any_port' | 'loopback_fixed_port' | 'unknown';
  /** Chosen `redirect_host` for the profile: first tolerated literal, else undefined. */
  redirect_host?: string;
  receipts: Receipt[];
}

function looksRejected(haystack: string): boolean {
  const low = haystack.toLowerCase();
  return REJECT_PATTERNS.some((p) => low.includes(p));
}

function buildRedirect(host: string, port: number): string {
  return `http://${host}:${port}${CALLBACK_PATH}`;
}

/** A high random port outside the fixed ladder — the "does it accept arbitrary ports?" probe. */
function randomHighPort(): number {
  return 40000 + Math.floor(Math.random() * 20000);
}

async function probeOne(
  authorizeUrl: string,
  clientId: string | undefined,
  host: string,
  port: number,
  kind: 'fixed' | 'random',
  http: ProbeHttp,
): Promise<RedirectProbe> {
  const redirectUri = buildRedirect(host, port);
  const url = new URL(authorizeUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId ?? 'handshake-probe');
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', 'handshake-probe-state');
  url.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  url.searchParams.set('code_challenge_method', 'S256');

  const res = await safeFetch(url.toString(), { http, redirect: 'manual' });
  const request = { method: 'GET', url: url.toString() };
  const mk = (outcome: RedirectOutcome, note: string, response?: Receipt['response']): RedirectProbe => ({
    host,
    port,
    kind,
    redirect_uri: redirectUri,
    outcome,
    receipt: {
      field: 'redirect_host',
      value: `${host} (${kind} port ${port}): ${outcome}`,
      method: 'authorize-redirect-tolerance',
      request,
      ...(response ? { response } : {}),
      note,
    },
  });

  if (!res.ok) {
    return mk('unknown', `transport failure: ${res.error ?? 'unreachable'}`);
  }

  const location = res.headers.location ?? '';
  const bodySample = evidenceBody(res.text);
  const response = { status: res.status, body: bodySample };

  // A redirect back to us (or its Location) that carries a redirect error = rejected.
  if (looksRejected(location) || looksRejected(res.text)) {
    return mk('rejected', `redirect explicitly refused${location ? ` (Location: ${evidenceBody(location)})` : ''}`, response);
  }

  // 3xx to the provider's own login/consent host = accepted far enough to be tolerated.
  if (res.status >= 300 && res.status < 400 && location !== '') {
    return mk('tolerated', `authorize bounced to consent/login (${evidenceBody(location)}) — redirect not refused`, response);
  }

  // A 200 consent page with no redirect complaint = tolerated.
  if (res.status === 200) {
    return mk('tolerated', 'authorize returned a page with no redirect complaint', response);
  }

  // Anything else (400/403 that does not name the redirect — usually an invalid client_id)
  // tells us nothing about redirect tolerance.
  return mk('unknown', `inconclusive (HTTP ${res.status}) — commonly the client_id, not the redirect`, response);
}

/**
 * Probe redirect tolerance across the fixed ladder port, a random high port, and each host
 * literal. `fixedPort` defaults to the first ladder rung; a valid `clientId` sharpens every
 * result. Returns per-candidate outcomes plus the aggregated `redirect` / `redirect_host`.
 */
export async function probeRedirectTolerance(
  authorizeUrl: string,
  clientId: string | undefined,
  http: ProbeHttp = {},
  fixedPort = 33418,
): Promise<RedirectToleranceResult> {
  const randomPort = randomHighPort();
  const probes: RedirectProbe[] = [];

  for (const host of LOOPBACK_HOSTS) {
    probes.push(await probeOne(authorizeUrl, clientId, host, fixedPort, 'fixed', http));
  }
  // Random-high-port probe only needs one host literal to answer the any-port question.
  const anyPortProbe = await probeOne(authorizeUrl, clientId, '127.0.0.1', randomPort, 'random', http);
  probes.push(anyPortProbe);

  const tolerated_hosts = [
    ...new Set(probes.filter((p) => p.kind === 'fixed' && p.outcome === 'tolerated').map((p) => p.host)),
  ];

  const fixedTolerated = probes.some((p) => p.kind === 'fixed' && p.outcome === 'tolerated');
  let redirect: RedirectToleranceResult['redirect'];
  if (anyPortProbe.outcome === 'tolerated') redirect = 'loopback_any_port';
  else if (fixedTolerated && anyPortProbe.outcome === 'rejected') redirect = 'loopback_fixed_port';
  else redirect = 'unknown';

  const receipts: Receipt[] = probes.map((p) => p.receipt);
  receipts.push({
    field: 'redirect',
    value: redirect,
    method: 'authorize-redirect-tolerance',
    note:
      redirect === 'unknown'
        ? `port-flexibility undetermined (fixed tolerated: ${fixedTolerated}, random ${randomPort}: ${anyPortProbe.outcome})`
        : `random high port ${randomPort} was ${anyPortProbe.outcome}`,
  });

  return {
    probes,
    tolerated_hosts,
    redirect,
    ...(tolerated_hosts.length > 0 ? { redirect_host: tolerated_hosts[0] } : {}),
    receipts,
  };
}
