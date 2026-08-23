/**
 * The one error type the engine throws across every boundary (work item W4).
 *
 * It lives in its own module rather than in `index.ts` for one structural reason: every
 * module below the public API needs to throw it, and `index.ts` imports every module. A
 * class defined at the top of that import graph and consumed at the bottom is an import
 * cycle by construction; a leaf module with zero imports is not. `index.ts` re-exports
 * this exact class, so `import { EngineError } from './index.ts'` keeps working and
 * `instanceof` keeps holding — there is one class, not two.
 *
 * Redaction rule (Dr. M): a token, refresh token, authorization code or PKCE verifier may
 * never appear in `message`, `hint` or `providerMessage` — VoiceOS writes MCP stderr to
 * disk, which is exactly the back door that would defeat "tokens never touch disk
 * unencrypted." `redact.ts` enforces this at the boundary; this class never formats a
 * credential into a string on its own.
 */

import type { EngineErrorCode } from './types.ts';

export class EngineError extends Error {
  readonly code: EngineErrorCode;
  /** Operator-facing next step. Safe to log. */
  readonly hint: string;
  /** The provider's own error text, verbatim, when there is one. */
  readonly providerMessage: string | undefined;

  constructor(
    code: EngineErrorCode,
    message: string,
    options: { hint?: string; providerMessage?: string; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'EngineError';
    this.code = code;
    this.hint = options.hint ?? '';
    this.providerMessage = options.providerMessage;
  }
}
