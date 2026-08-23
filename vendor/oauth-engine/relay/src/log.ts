/**
 * The relay's only log. It is credential-free BY CONSTRUCTION, not by discipline.
 *
 * The problem with "just don't log secrets" is that it is a rule a human has to keep, and the
 * one time someone logs `req.body` to debug a 400 is the time a token lands on disk. So this
 * logger does not accept free-form objects. It accepts a `RelayEvent`, a closed shape whose
 * every field is a bounded, non-secret enum or number. There is no field a code, verifier,
 * token, assertion, secret, or ciphertext can be placed into — the type system refuses it.
 *
 * A relay that logs to stdout is a relay whose operator's log aggregator now holds whatever it
 * logged. Making it structurally impossible to log a credential is the point (SPEC §5: "logs
 * any credential material" is on the NEVER list).
 */

export type RelayEventName =
  | 'assertion.signed' // B2a: an assertion was signed and returned
  | 'exchange.forwarded' // B2b: one exchange was performed and sealed
  | 'request.rejected'; // a request was refused before any credential was touched

export type RelayOutcome = 'ok' | 'error';

/**
 * A log line. Every field is metadata: which mode ran, for which provider, how it ended, how
 * long it took, and an upstream HTTP status when there is one. Nothing here can carry a token.
 */
export interface RelayEvent {
  event: RelayEventName;
  provider: string;
  outcome: RelayOutcome;
  ms: number;
  /** Upstream HTTP status (B2b only). */
  provider_status?: number;
  /** A typed error code (never a message that could contain provider text). */
  error_code?: string;
}

export type LogSink = (line: string) => void;

/**
 * The logger. `sink` defaults to stdout; tests pass a capturing sink and then assert no token
 * value ever appears in what was captured.
 */
export class RelayLog {
  #sink: LogSink;

  constructor(sink: LogSink = (line) => process.stdout.write(`${line}\n`)) {
    this.#sink = sink;
  }

  emit(event: RelayEvent): void {
    // Serialize only the known-safe fields, in a fixed order. Even if a caller somehow passed
    // an object with extra keys, they are dropped here — the emitted line is a whitelist.
    const safe: RelayEvent = {
      event: event.event,
      provider: event.provider,
      outcome: event.outcome,
      ms: event.ms,
      ...(event.provider_status === undefined ? {} : { provider_status: event.provider_status }),
      ...(event.error_code === undefined ? {} : { error_code: event.error_code }),
    };
    this.#sink(JSON.stringify({ t: new Date().toISOString(), ...safe }));
  }
}
