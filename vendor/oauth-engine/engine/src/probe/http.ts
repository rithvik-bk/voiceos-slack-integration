/**
 * The probe's one HTTP primitive (C-1). Deliberately safe: GET/POST, hard timeout,
 * `redirect: 'error'` (a 3xx is data the probe classifies, never a hop it silently follows),
 * and it NEVER throws on a non-2xx — an HTTP 401/400/404 is the measurement, not a fault.
 *
 * The only thrown-equivalent is a transport failure (DNS, refused connection, timeout),
 * which is returned as `{ ok:false, status:0, error }` so the caller records an honest
 * `unknown` receipt rather than crashing a matrix run halfway through.
 *
 * Zero dependencies, mirrors exchange.ts's fetch discipline (AbortController + finally clear).
 */

import { redact } from '../redact.ts';
import type { ProbeHttp } from './types.ts';

/** A probe never waits longer than this on a single request — a hung provider is a datum. */
const PROBE_TIMEOUT_MS = 15_000;

/** Response bodies are capped in evidence: a projector never renders a proxy dump. */
export const MAX_BODY_CHARS = 800;

export interface SafeResponse {
  /** True when the server answered with any HTTP status; false on transport failure. */
  ok: boolean;
  /** HTTP status, or 0 when the network never reached a server. */
  status: number;
  /** Raw response text (used only to parse; the evidence copy is redacted + capped). */
  text: string;
  /** Parsed JSON body, or `undefined` when the body was not JSON. */
  json: unknown;
  /** Lowercased response header map. */
  headers: Record<string, string>;
  /** Redacted transport-failure message when `ok` is false. */
  error?: string;
}

export interface SafeRequestInit {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  http?: ProbeHttp;
  /**
   * Redirect handling. Defaults to `'error'` — a 3xx is a fault the probe never follows.
   * Authorize-tolerance probing sets `'manual'` so a 302 to a login page is READ (status +
   * Location) rather than turned into a transport failure.
   */
  redirect?: 'error' | 'manual';
}

/** One safe request. Resolves for every server answer; only transport death sets `ok:false`. */
export async function safeFetch(url: string, init: SafeRequestInit = {}): Promise<SafeResponse> {
  const http = init.http ?? {};
  const doFetch = http.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), http.timeoutMs ?? PROBE_TIMEOUT_MS);

  let response: Response;
  try {
    response = await doFetch(url, {
      method: init.method ?? 'GET',
      headers: {
        accept: 'application/json',
        ...(init.headers ?? {}),
      },
      ...(init.body === undefined ? {} : { body: init.body }),
      signal: controller.signal,
      redirect: init.redirect ?? 'error',
    });
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : 'network failure';
    return { ok: false, status: 0, text: '', json: undefined, headers: {}, error: redact(detail) };
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  return { ok: true, status: response.status, text, json, headers };
}

/**
 * The redacted, length-capped body snapshot that goes into a receipt. A body is a URL-encoded
 * form or a JSON error; either way it is scrubbed of credential-shaped runs and clipped so
 * evidence is safe to publish and safe to read aloud.
 */
export function evidenceBody(text: string): string {
  const scrubbed = redact(text);
  return scrubbed.length > MAX_BODY_CHARS ? `${scrubbed.slice(0, MAX_BODY_CHARS - 1)}…` : scrubbed;
}
