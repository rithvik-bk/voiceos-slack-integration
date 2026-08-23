/**
 * C-21 — `auth.client()`, the zero-auth-code wrapper (SPEC §18).
 *
 * The target is not "auth is easy." The target is "auth is ABSENT from integration code":
 *
 *     const api = auth.client("slack");
 *     const res = await api.post("/chat.postMessage", { channel, text });
 *
 * There is no token variable in the author's code because there is no place for one. This
 * module is the object that makes that true. It returns a fetch-shaped client
 * (`.get/.post/.put/.patch/.delete/.head/.fetch`) that, on every call:
 *
 *   1. injects the credential for (provider, account) — resolving the account exactly the way
 *      {@link getToken} does, so a two-workspace user is handled without the author knowing;
 *   2. refreshes silently before expiry and RETRIES EXACTLY ONCE on a 401 after a successful
 *      refresh — reusing the cross-process-locked refresh in refresh.ts, never a second copy;
 *   3. applies the sender-constraint scheme the profile requires — a fresh RFC 9449 DPoP proof
 *      per request for `sender_constraint: 'dpop'`, the RFC 8705 client-certificate transport
 *      for `'mtls'`, plain Bearer otherwise;
 *   4. raises the scope step-up card (SPEC §9) BEFORE dispatch when an action declares a scope
 *      the grant does not hold — never inside the call, never as a 3am tool failure;
 *   5. throws the closed 9-code taxonomy (SPEC §15) for every auth/availability failure, so
 *      tool code branches on nine cases forever and never on a provider's error vocabulary.
 *
 * INV-CONFIG-1 holds here too: every branch above is on a capability VALUE
 * (`sender_constraint`, `scope_grant`, an HTTP status), never on a provider name.
 *
 * Structure note: this module takes its profile resolver as an injected dependency rather than
 * importing it from `index.ts`, because `index.ts` imports THIS file to publish it — importing
 * back would be a cycle. `index.ts` wires {@link createAuthClient} with its own `resolveProfile`.
 */

import type { AccountRef } from './account.ts';
import { AccountAmbiguousError, emptyIndex, resolveAccountOrThrow } from './account.ts';
import { createDpopSigner, dpopNonceChallenge, type DpopSigner } from './dpop.ts';
import { EngineError } from './errors.ts';
import { satisfiesPredicate } from './exchange.ts';
import { readFirstString } from './paths.ts';
import { authorizedFetch, getFreshToken, isAuthFailure } from './refresh.ts';
import {
  normalizeScopes,
  planStepUp,
  type StepUpMode,
  type StepUpTrigger,
} from './scope.ts';
import {
  fromOAuthError,
  normalize,
  normalizeEngineError,
  recommendedAction,
  type NormalizedError,
  type TaxonomyCode,
} from './taxonomy.ts';
import { readAccountIndex, readToken } from './vault.ts';
import type { ProviderProfile } from './types.ts';

/* ─────────────────────────────── the thrown error ─────────────────────────────── */

/**
 * The step-up card the wrapper raises when an action needs an ungranted scope (SPEC §9). The
 * product surface catches it on a {@link TaxonomyError} and re-runs
 * `connect(profile, { scopes: requestScopes, force: true })` to present the consent card that
 * names `addedScopes`. Everything the surface needs to raise the card is here — the author's
 * tool code did nothing but declare `requiresScopes`.
 */
export interface StepUpCard {
  provider: string;
  account?: string;
  /** The scopes newly being added — what the consent card names to the user. */
  addedScopes: string[];
  /** The EXACT scope set to send on the step-up authorize request (union rule applied). */
  requestScopes: string[];
  /** `incremental` = request the delta alone; `union` = re-request granted ∪ needed. */
  mode: StepUpMode;
}

/**
 * The one error `auth.client()` throws across its boundary: a normalized, closed-set taxonomy
 * failure (SPEC §15). `code` is one of nine; `action` is a safe-to-display next step; a genuine
 * provider error string rides in `rawProviderError` for debugging (never a credential). A
 * scope step-up carries its `stepUp` card; an ambiguous account carries `candidates`.
 *
 * It is deliberately NOT an {@link EngineError}: EngineError's codes are the engine's internal
 * vocabulary, and the whole point of the taxonomy is that an integration author never sees that
 * vocabulary. One class, `code` in {@link TaxonomyCode}, nine cases forever.
 */
export class TaxonomyError extends Error {
  readonly code: TaxonomyCode;
  readonly action: string;
  readonly rawProviderError?: string;
  readonly status?: number;
  readonly stepUp?: StepUpCard;
  readonly candidates?: AccountRef[];

  constructor(
    normalized: NormalizedError,
    extra: { status?: number; stepUp?: StepUpCard; candidates?: AccountRef[]; cause?: unknown } = {},
  ) {
    super(normalized.action, extra.cause === undefined ? undefined : { cause: extra.cause });
    this.name = 'TaxonomyError';
    this.code = normalized.code;
    this.action = normalized.action;
    if (normalized.rawProviderError !== undefined) this.rawProviderError = normalized.rawProviderError;
    if (extra.status !== undefined) this.status = extra.status;
    if (extra.stepUp !== undefined) this.stepUp = extra.stepUp;
    if (extra.candidates !== undefined) this.candidates = extra.candidates;
  }
}

/** Build a {@link TaxonomyError} straight from a code with a custom action (used where the
 *  default action is not specific enough, e.g. a missing mTLS transport). */
function taxonomyError(
  code: TaxonomyCode,
  extra: {
    action?: string;
    rawProviderError?: string;
    status?: number;
    stepUp?: StepUpCard;
    candidates?: AccountRef[];
    cause?: unknown;
  } = {},
): TaxonomyError {
  const normalized: NormalizedError = {
    code,
    action: extra.action ?? recommendedAction(code),
    ...(extra.rawProviderError === undefined ? {} : { rawProviderError: extra.rawProviderError }),
  };
  return new TaxonomyError(normalized, {
    ...(extra.status === undefined ? {} : { status: extra.status }),
    ...(extra.stepUp === undefined ? {} : { stepUp: extra.stepUp }),
    ...(extra.candidates === undefined ? {} : { candidates: extra.candidates }),
    ...(extra.cause === undefined ? {} : { cause: extra.cause }),
  });
}

/* ─────────────────────────────── the client surface ─────────────────────────────── */

/**
 * `fetch`-init plus the two annotations that drive step-up. `requiresScopes` declares the
 * scopes THIS action needs (SPEC §9's `requires_scopes`); `trigger` is the provenance that
 * authorizes an escalation — a content-triggered escalation is refused (§9). A VoiceOS tool
 * call originates from a spoken command, so `trigger` defaults to `user_transcript`.
 */
export interface ClientRequestInit extends RequestInit {
  requiresScopes?: string[];
  trigger?: StepUpTrigger;
}

/** The fetch-shaped object an integration's tools actually hold. */
export interface AuthClient {
  readonly provider: string;
  readonly account?: string;
  fetch(path: string, init?: ClientRequestInit): Promise<Response>;
  get(path: string, init?: ClientRequestInit): Promise<Response>;
  post(path: string, body?: unknown, init?: ClientRequestInit): Promise<Response>;
  put(path: string, body?: unknown, init?: ClientRequestInit): Promise<Response>;
  patch(path: string, body?: unknown, init?: ClientRequestInit): Promise<Response>;
  delete(path: string, init?: ClientRequestInit): Promise<Response>;
  head(path: string, init?: ClientRequestInit): Promise<Response>;
}

export interface AuthClientOptions {
  /**
   * Transport override. Injected in tests; for `sender_constraint: 'mtls'` this is where the
   * caller supplies a client-certificate-bound transport (Node's global fetch cannot attach a
   * client cert on its own), since the mTLS binding lives at the TLS layer (RFC 8705).
   */
  fetchImpl?: typeof fetch;
  /** Default step-up provenance when a call sets `requiresScopes` but no `trigger`. */
  defaultTrigger?: StepUpTrigger;
  /**
   * When false, non-2xx and body-predicate failures are RETURNED as a `Response` (pure fetch
   * semantics) instead of thrown as a {@link TaxonomyError}. Not-connected, ambiguous-account,
   * and step-up still throw, because there is no `Response` to hand back. Default true.
   */
  throwOnErrorResponses?: boolean;
  /** Injected in tests for a deterministic DPoP key; production generates a fresh keypair. */
  dpopSigner?: DpopSigner;
}

/** The one dependency this module takes from the layer above it, to avoid an import cycle. */
export interface CreateAuthClientDeps {
  resolveProfile(provider: string): Promise<ProviderProfile>;
}

const DEFAULT_TRIGGER: StepUpTrigger = { attribution: 'user_transcript' };

/** HTTP statuses on which the wrapper throws the taxonomy rather than returning the Response. */
function isThrowableStatus(status: number): boolean {
  return status === 401 || status === 403 || status === 429 || status >= 500;
}

/** Taxonomy codes that represent an auth/availability failure worth throwing on a 200 body. */
const BODY_THROWABLE: ReadonlySet<TaxonomyCode> = new Set<TaxonomyCode>([
  'TOKEN_EXPIRED',
  'REVOKED',
  'SCOPE_INSUFFICIENT',
  'RATE_LIMITED',
  'PROVIDER_UNAVAILABLE',
  'REFRESH_FAILED',
  'NOT_CONNECTED',
]);

/**
 * Pull the provider's own error token from a response body, redaction-safe: only the short
 * `error` / `error_description` / `message` field, capped, never the whole body (which could
 * carry user content) and never a credential. Reads a CLONE so the caller's Response is intact.
 */
async function extractProviderError(response: Response): Promise<string | undefined> {
  let payload: unknown;
  try {
    payload = await response.clone().json();
  } catch {
    return undefined;
  }
  // Candidate list = a set of dotted paths, most-specific first: a top-level `error` string,
  // then a nested `error.code`/`error.status`/`error.message`, then the OAuth `error_description`,
  // then a bare `message`. Each is one path; the first that yields a string wins.
  const token = readFirstString(payload, [
    'error',
    'error.code',
    'error.status',
    'error.message',
    'error_description',
    'message',
  ]);
  if (token === undefined || token === '') return undefined;
  return token.length > 200 ? token.slice(0, 200) : token;
}

function bodyPredicatePassed(profile: ProviderProfile, payload: unknown): boolean {
  if (profile.success_predicate === undefined || profile.success_predicate === null) return true;
  return satisfiesPredicate(profile.success_predicate, payload);
}

/**
 * Decide whether a response is an auth/availability failure the wrapper should throw on, or a
 * response the caller owns (a 2xx, or a business-level 4xx like 404/409). Returns the
 * normalized error to throw, or null to return the Response untouched.
 */
async function classifyResponse(
  profile: ProviderProfile,
  response: Response,
): Promise<NormalizedError | null> {
  if (response.ok) {
    // A 200 can still be a Slack-style `{"ok": false}` failure. Only throw when the body's
    // error token is an AUTH/scope/rate signal; a domain error (channel_not_found) is the
    // caller's Response, not ours.
    if (profile.success_predicate === undefined || profile.success_predicate === null) return null;
    let payload: unknown;
    try {
      payload = await response.clone().json();
    } catch {
      return null;
    }
    if (bodyPredicatePassed(profile, payload)) return null;
    const token = readFirstString(payload, ['error']);
    const code = token === undefined ? undefined : fromOAuthError(token);
    if (token !== undefined && code !== undefined && BODY_THROWABLE.has(code)) {
      return normalize({ providerError: token });
    }
    return null;
  }

  if (!isThrowableStatus(response.status)) return null;
  const token = await extractProviderError(response);
  return normalize({
    status: response.status,
    ...(token === undefined ? {} : { providerError: token }),
  });
}

/** Resolve a request path against the profile's `api_base`; absolute URLs pass through. */
function resolveUrl(profile: ProviderProfile, path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  const base = profile.api_base;
  if (base === undefined || base === '') {
    throw new EngineError('config_invalid', `${profile.name} has no api_base to resolve '${path}'`, {
      hint: `Pass an absolute https URL, or set "api_base" in ${profile.name}'s provider.json.`,
    });
  }
  // Treat api_base as a PREFIX: force a trailing slash on the base and strip a leading slash
  // from the path, so `https://slack.com/api` + `/chat.postMessage` → `.../api/chat.postMessage`
  // rather than resetting to the origin the way a leading-slash URL resolution would.
  return new URL(path.replace(/^\/+/, ''), base.replace(/\/*$/, '/')).toString();
}

const PASSTHROUGH_BODY = (body: unknown): boolean =>
  typeof body === 'string' ||
  body instanceof ArrayBuffer ||
  ArrayBuffer.isView(body) ||
  (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) ||
  (typeof FormData !== 'undefined' && body instanceof FormData) ||
  (typeof Blob !== 'undefined' && body instanceof Blob) ||
  (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream);

/** Build the RequestInit for the outgoing call, JSON-encoding a plain-object body. */
function buildInit(method: string, clientInit: ClientRequestInit, body: unknown): RequestInit {
  const { requiresScopes: _rs, trigger: _t, headers, body: initBody, ...rest } = clientInit;
  const outHeaders: Record<string, string> = { ...(headers as Record<string, string> | undefined) };
  const init: RequestInit = { ...rest, method };

  const effectiveBody = body !== undefined ? body : initBody;
  if (effectiveBody !== undefined && method !== 'GET' && method !== 'HEAD') {
    if (PASSTHROUGH_BODY(effectiveBody)) {
      init.body = effectiveBody as NonNullable<RequestInit['body']>;
    } else {
      init.body = JSON.stringify(effectiveBody);
      const hasContentType = Object.keys(outHeaders).some((h) => h.toLowerCase() === 'content-type');
      if (!hasContentType) outHeaders['content-type'] = 'application/json';
    }
  }
  init.headers = outHeaders;
  return init;
}

/**
 * The DPoP resource-request loop (RFC 9449). Distinct from the Bearer path because a DPoP
 * NONCE CHALLENGE is a 401 that must NOT spend a refresh token — the fix is to re-sign with the
 * server's nonce, not to rotate the grant. So the order is: send → adopt a nonce and retry with
 * the SAME token if challenged → only then, on a genuine auth failure, refresh once and retry.
 * The refresh itself goes through the same cross-process-locked {@link getFreshToken}.
 *
 * Honest scope limit (documented, not hidden): this binds RESOURCE requests. Binding the token
 * at the token endpoint (a DPoP proof on exchange/refresh) is the exchange-side concern C-19,
 * separate from this wrapper (C-21).
 */
async function dpopFetch(
  profile: ProviderProfile,
  url: string,
  init: RequestInit,
  opts: { accountId?: string; fetchImpl?: typeof fetch; signer: DpopSigner },
): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const method = (init.method ?? 'GET').toUpperCase();
  let nonce: string | undefined;

  const send = (token: string): Promise<Response> => {
    const proof = opts.signer.proof({
      method,
      url,
      accessToken: token,
      ...(nonce === undefined ? {} : { nonce }),
    });
    return doFetch(url, {
      ...init,
      headers: {
        ...(profile.static_headers ?? {}),
        ...(init.headers as Record<string, string> | undefined),
        authorization: `DPoP ${token}`,
        dpop: proof,
      },
    });
  };

  const refreshOpts = {
    ...(opts.accountId === undefined ? {} : { accountId: opts.accountId }),
    ...(opts.fetchImpl === undefined ? {} : { fetchImpl: opts.fetchImpl }),
  };

  let token = await getFreshToken(profile, refreshOpts);
  let response = await send(token);

  const challenge = dpopNonceChallenge(response);
  if (challenge !== undefined) {
    nonce = challenge;
    response = await send(token);
  }

  if (await isAuthFailure(profile, response)) {
    token = await getFreshToken(profile, { ...refreshOpts, force: true });
    response = await send(token);
    const c2 = dpopNonceChallenge(response);
    if (c2 !== undefined) {
      nonce = c2;
      response = await send(token);
    }
  }

  return response;
}

/**
 * The Bearer path, reusing the tested silent-refresh + on-401-retry-once in refresh.ts so
 * there is exactly one copy of that logic. `mtls` also lands here (the token is a Bearer per
 * RFC 8705 §3; the sender constraint is the TLS client cert on the supplied transport).
 */
async function bearerFetch(
  profile: ProviderProfile,
  url: string,
  init: RequestInit,
  opts: { accountId?: string; fetchImpl?: typeof fetch },
): Promise<Response> {
  return authorizedFetch(profile, url, init, {
    ...(opts.accountId === undefined ? {} : { accountId: opts.accountId }),
    ...(opts.fetchImpl === undefined ? {} : { fetchImpl: opts.fetchImpl }),
  });
}

/* ─────────────────────────────── the factory ─────────────────────────────── */

/**
 * Build an {@link AuthClient} for (provider, account). The profile and account are resolved
 * LAZILY on first request (and cached), so `auth.client("slack")` is synchronous and cheap —
 * matching the SPEC §18 example, where the client is created without an `await`.
 */
export function createAuthClient(
  deps: CreateAuthClientDeps,
  provider: string,
  account?: string,
  options: AuthClientOptions = {},
): AuthClient {
  const throwOnErrors = options.throwOnErrorResponses !== false;
  const defaultTrigger = options.defaultTrigger ?? DEFAULT_TRIGGER;

  let profilePromise: Promise<ProviderProfile> | undefined;
  const profile = (): Promise<ProviderProfile> => {
    profilePromise ??= deps.resolveProfile(provider);
    return profilePromise;
  };

  let accountIdPromise: Promise<string | undefined> | undefined;
  const accountId = (): Promise<string | undefined> => {
    accountIdPromise ??= (async () => {
      const index = await readAccountIndex(provider).catch(() => emptyIndex());
      // Back-compat: no index yet (a legacy single-slot record) → the bare provider key.
      if (index.accounts.length === 0) return undefined;
      return resolveAccountOrThrow(provider, index, account).accountId;
    })();
    return accountIdPromise;
  };

  let signer: DpopSigner | undefined = options.dpopSigner;
  const dpopSigner = (): DpopSigner => {
    signer ??= createDpopSigner();
    return signer;
  };

  async function request(
    method: string,
    path: string,
    clientInit: ClientRequestInit,
    body: unknown,
  ): Promise<Response> {
    let prof: ProviderProfile;
    let acct: string | undefined;
    try {
      prof = await profile();
      acct = await accountId();
    } catch (error) {
      throw toTaxonomy(error);
    }

    // Step-up gate — BEFORE dispatch (SPEC §9), never inside the call.
    const required = normalizeScopes(clientInit.requiresScopes ?? []);
    if (required.length > 0) {
      const record = await readToken(prof.name, acct).catch(() => null);
      if (record === null) {
        throw taxonomyError('NOT_CONNECTED');
      }
      const decision = planStepUp({
        ...(prof.scope_grant === undefined ? {} : { scopeGrant: prof.scope_grant }),
        grantedScopes: record.scopes,
        requiredScopes: required,
        trigger: clientInit.trigger ?? defaultTrigger,
      });
      if (decision.kind === 'refused') {
        throw taxonomyError('SCOPE_INSUFFICIENT', {
          action:
            'This action needs a permission that was not granted, and the request was not initiated by the user. Ask the user to trigger it, then reconnect to approve.',
        });
      }
      if (decision.kind === 'step_up') {
        throw taxonomyError('SCOPE_INSUFFICIENT', {
          stepUp: {
            provider: prof.name,
            ...(account === undefined ? {} : { account }),
            addedScopes: decision.addedScopes,
            requestScopes: decision.requestScopes,
            mode: decision.mode,
          },
        });
      }
    }

    let url: string;
    try {
      url = resolveUrl(prof, path);
    } catch (error) {
      throw toTaxonomy(error);
    }
    const init = buildInit(method, clientInit, body);

    let response: Response;
    try {
      const constraint = prof.sender_constraint;
      if (constraint === 'dpop') {
        response = await dpopFetch(prof, url, init, {
          ...(acct === undefined ? {} : { accountId: acct }),
          ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
          signer: dpopSigner(),
        });
      } else if (constraint === 'mtls') {
        if (options.fetchImpl === undefined) {
          throw taxonomyError('CONFIG_INVALID', {
            action:
              'This provider is mTLS sender-constrained: supply a client-certificate transport (auth.client(provider, account, { fetchImpl })) so the token can be bound to the TLS client certificate.',
          });
        }
        response = await bearerFetch(prof, url, init, {
          ...(acct === undefined ? {} : { accountId: acct }),
          fetchImpl: options.fetchImpl,
        });
      } else {
        response = await bearerFetch(prof, url, init, {
          ...(acct === undefined ? {} : { accountId: acct }),
          ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
        });
      }
    } catch (error) {
      throw toTaxonomy(error);
    }

    if (!throwOnErrors) return response;
    const failure = await classifyResponse(prof, response);
    if (failure !== null) {
      throw new TaxonomyError(failure, { status: response.status });
    }
    return response;
  }

  return {
    provider,
    ...(account === undefined ? {} : { account }),
    fetch: (path, init = {}) => request((init.method ?? 'GET').toUpperCase(), path, init, undefined),
    get: (path, init = {}) => request('GET', path, init, undefined),
    post: (path, body, init = {}) => request('POST', path, init, body),
    put: (path, body, init = {}) => request('PUT', path, init, body),
    patch: (path, body, init = {}) => request('PATCH', path, init, body),
    delete: (path, init = {}) => request('DELETE', path, init, undefined),
    head: (path, init = {}) => request('HEAD', path, init, undefined),
  };
}

/** Map any error raised inside a request into the closed taxonomy. */
function toTaxonomy(error: unknown): TaxonomyError {
  if (error instanceof TaxonomyError) return error;
  if (error instanceof AccountAmbiguousError) {
    return taxonomyError('CONFIG_INVALID', {
      action: error.hint || error.message,
      candidates: error.candidates,
    });
  }
  if (error instanceof EngineError) {
    return new TaxonomyError(
      normalizeEngineError({
        code: error.code,
        ...(error.providerMessage === undefined ? {} : { providerMessage: error.providerMessage }),
      }),
    );
  }
  // A transport/network throw (fetch rejects with a TypeError) is a provider-availability
  // failure, not a bug to leak as a raw stack.
  return taxonomyError('PROVIDER_UNAVAILABLE', {
    ...(error instanceof Error ? { cause: error } : {}),
  });
}
