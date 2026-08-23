/**
 * The identity probe — the reason `connected` is a fact and not a hope.
 *
 * Copy deck, verbatim: **"`connected` is produced by an identity probe, never by an HTTP
 * 200."** Slack will answer a token request with HTTP 200 and `{"ok": false}` [C-SL-20];
 * an engine that reports success on the status code would put "Connected as …" on the
 * projector while holding nothing. Reporting a connection that does not exist is exactly the
 * class of unverified claim this engine refuses to make, so the check is structural, not a nicety.
 *
 * The probe doubles as the source of the spoken line: `auth.test` returns the handle and
 * the workspace, which is what makes the demo say "Connected as Rithvik in VoiceOS HQ"
 * instead of "Connected."
 */

import { EngineError } from './errors.ts';
import { satisfiesPredicate } from './exchange.ts';
import { readFirstString } from './paths.ts';
import { safeProviderMessage } from './redact.ts';
import type { ProviderProfile } from './types.ts';

export interface Identity {
  handle: string;
  workspace?: string;
  accountId?: string;
  /**
   * The OIDC `sub` claim. When a provider (or a caller) supplies the immutable subject under
   * its standard name rather than as {@link accountId}, it is treated as an opaque account-id
   * alias — so two accounts sharing a mutable handle but differing in `sub` stay distinct.
   */
  sub?: string;
}

const PROBE_TIMEOUT_MS = 10_000;

/**
 * Ask the provider who this token belongs to.
 *
 * @throws EngineError `expired_or_revoked` when the provider says the token is not good.
 * @throws EngineError `provider_error` for anything else, carrying the provider's own words.
 */
export async function probeIdentity(
  profile: ProviderProfile,
  accessToken: string,
  options: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<Identity> {
  const probe = profile.identity_probe;
  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? PROBE_TIMEOUT_MS);

  let response: Response;
  try {
    response = await doFetch(probe.url, {
      method: probe.method ?? 'GET',
      headers: {
        accept: 'application/json',
        ...(profile.static_headers ?? {}),
        ...(probe.auth === 'none' ? {} : { authorization: `Bearer ${accessToken}` }),
      },
      signal: controller.signal,
    });
  } catch (cause) {
    throw new EngineError('provider_error', 'the identity probe could not reach the provider', {
      hint: `${probe.method ?? 'GET'} ${probe.url} failed. "Connected" is never claimed without this call.`,
      cause,
    });
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new EngineError('provider_error', 'the identity probe returned a non-JSON body', {
      hint: `HTTP ${response.status} from ${probe.url}.`,
    });
  }

  const bodyOk = satisfiesPredicate(probe.success_predicate, payload);
  if (!response.ok || !bodyOk) {
    // The token is redacted out of anything we surface: it is in scope right here.
    const providerMessage = safeProviderMessage(payload, [accessToken]);
    const dead = response.status === 401 || response.status === 403 || (response.ok && !bodyOk);
    throw new EngineError(
      dead ? 'expired_or_revoked' : 'provider_error',
      `${profile.name} rejected the identity probe`,
      {
        hint: `HTTP ${response.status} from ${probe.url}. A token that cannot identify itself is not a connection.`,
        ...(providerMessage === undefined ? {} : { providerMessage }),
      },
    );
  }

  const handle = readFirstString(payload, [probe.handle_path]);
  if (handle === undefined) {
    throw new EngineError('provider_error', `${profile.name} returned no identity handle`, {
      hint: `identity_probe.handle_path '${probe.handle_path}' does not match the response shape.`,
    });
  }

  const workspace = readFirstString(payload, [probe.workspace_path]);
  const accountId = readFirstString(payload, [probe.account_id_path]);

  return {
    handle: `${probe.handle_prefix ?? ''}${handle}`,
    ...(workspace === undefined ? {} : { workspace }),
    ...(accountId === undefined ? {} : { accountId }),
  };
}
