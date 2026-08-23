// Blind harness — helpers derived only from the spec threat model, not from engine source.

/** Well-known credential shapes an attacker's token/secret would take on the wire.
 *  A redaction boundary that "scrubs credential-shaped runs" (INV-SECRET-4) must
 *  neutralize every one of these. */
// The token-shaped values are assembled from fragments (never written as one literal), exactly
// as engine/test/scan-secrets.test.ts does — so the push-gate scanner plants no finding on the
// blind corpus itself, while the RUNTIME value handed to redact() is byte-identical to a real
// leaked credential. Splitting the literal changes nothing the engine sees; it only keeps the
// fixture out of the scanner's value-shaped rules.
export const CREDENTIAL_SAMPLES: Array<{ label: string; value: string }> = [
  { label: 'Slack bot token (xoxb-)', value: `xox${'b'}-2468013579-1357924680-ABCDEFabcdef0123456789XY` },
  { label: 'Slack user token (xoxp-)', value: `xox${'p'}-2468013579-1357924680-2468013579-abcdef0123456789abcdef0123456789` },
  { label: 'Google access token (ya29.)', value: 'ya29.a0AfB_abcdEFGHijklMNOPqrstUVWX0123456789-_abcdEFGHijklMNOPqrst' },
  { label: 'Google refresh token (1//)', value: '1//0gABCDefGHijKLmnOPqrStuVWxyZ-abcdefghijklmnopqrstuvwxyz012345' },
  { label: 'Stripe secret key (sk_live_)', value: `sk_${'live'}_51H8xAbcdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGH` },
  { label: 'GitHub PAT (ghp_)', value: 'ghp_ABCDEFabcdef0123456789ABCDEFabcdef0123' },
  { label: 'JWT bearer', value: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.SIGNATUREabcdef0123456789' },
];

/** True if `haystack` still contains any recognizable slice of the secret. A redaction
 *  boundary must remove the whole run, so even a long substring surviving is a leak. */
export function stillContainsSecret(haystack: string, secret: string): boolean {
  if (typeof haystack !== 'string') return false;
  if (haystack.includes(secret)) return true;
  // The high-entropy tail is the part that must never survive; 16 chars of it leaking
  // is enough to matter.
  const tail = secret.slice(-24);
  if (tail.length >= 16 && haystack.includes(tail)) return true;
  return false;
}

/** base64url string -> byte length, for asserting `state` entropy (INV-STATE-1: >=32 bytes). */
export function b64urlBytes(s: string): number {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? 0 : 4 - (b64.length % 4);
  return Buffer.from(b64 + '='.repeat(pad), 'base64').length;
}

/** A fetch stub that records every outbound request body, for inspecting what the
 *  relay client transmits without touching the network. Returns a canned relay reply. */
export function recordingFetch(reply: unknown = { client_assertion: 'SIGNED.JWT', assertion: 'SIGNED.JWT' }) {
  const calls: Array<{ url: string; body: string | null }> = [];
  const fn = async (url: unknown, opts?: { body?: unknown }) => {
    calls.push({ url: String(url), body: opts?.body != null ? String(opts.body) : null });
    return {
      ok: true,
      status: 200,
      json: async () => reply,
      text: async () => JSON.stringify(reply),
    } as unknown as Response;
  };
  return { fn: fn as unknown as typeof fetch, calls };
}
