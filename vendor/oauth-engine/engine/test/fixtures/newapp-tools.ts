/**
 * FIXTURE — a brand-new integration's entire tool file, written the way SPEC §18 promises:
 * with ZERO lines of authorization code. This is the falsifiable artifact behind
 * "auth LOC in a new integration = 0" (C-21).
 *
 * The whole auth surface is one line — `auth.client("newapp")` — and nothing below it names a
 * token, a Bearer header, a refresh, PKCE, an exchange, or a client secret. `client-zero-auth.test.ts`
 * greps THIS FILE for every one of those constructs and asserts none exist, and then runs these
 * tools against a live mock provider to prove the file authenticates for real anyway.
 *
 * It is committed under test/fixtures and never wired into a real integration; it exists to be
 * measured. If a future refactor forces an auth line back into a tool file, the grep goes red.
 */

import { auth } from '../../src/index.ts';

/** Read the connected account's identity. No token in sight. */
export async function whoAmI(): Promise<{ display_name?: string; id?: string }> {
  const api = auth.client('newapp');
  const res = await api.get('/api/identity');
  return (await res.json()) as { display_name?: string; id?: string };
}

/** Post a message. The body is a plain object; the client encodes and authenticates it. */
export async function createThing(name: string): Promise<Response> {
  const api = auth.client('newapp');
  return api.post('/api/things', { name });
}

/** A write that declares the scope it needs; step-up is the engine's problem, not this file's. */
export async function deleteThing(id: string): Promise<Response> {
  const api = auth.client('newapp');
  return api.delete(`/api/things/${id}`, { requiresScopes: ['things:write'] });
}
