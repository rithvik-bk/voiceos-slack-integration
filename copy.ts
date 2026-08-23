/**
 * The frozen copy deck, as code.
 *
 * Every user-visible string this integration can produce lives in this file and nowhere
 * else. No model ever writes a word the user hears: there is no LLM anywhere in this path,
 * so the spoken and rendered copy is fixed, reviewable, and cannot drift at runtime.
 *
 * Placeholders are `{name}` and are filled by the render helpers below, never by string
 * concatenation at the call site, so a caller cannot invent a sentence.
 */

/** Rows of the copy deck, verbatim. `{handle}` / `{workspace}` / `{reason}` are the deck's own variables. */
export const DECK = {
  /** Deck row `needs_connect`. Its second sentence is a PROMISE: only speak it while actually opening. */
  needs_connect: "Your Slack isn't connected yet. I'm opening the approval page now.",
  opening_browser: 'Opening Slack in your browser.',
  awaiting_consent: 'Waiting for you to hit Allow.',
  exchanging: 'Got it. Verifying.',
  /** Deck row reads "Connected as Rithvik in VoiceOS HQ." — the handle and workspace come from the identity probe. */
  connected: 'Connected as {handle} in {workspace}.',
  denied_by_user: "You declined that one. Say 'connect Slack' whenever you want to retry.",
  port_blocked: "Something else is using my callback port. Close it and I'll retry.",
  expired_or_revoked: 'That connection expired. Reconnecting. One tap on Allow.',
  state_mismatch: "That reply didn't match my request, so I threw it away. Try connecting again.",
  timeout: "I stopped waiting for that approval. Say 'connect Slack' when you're ready.",
  /** `{reason}` is Slack's OWN error string, verbatim — never our paraphrase. */
  provider_error: 'Slack turned that down: {reason}. Nothing was connected.',
  /**
   * Deck row `empty_channel` (ratified 2026-08-16). A successful read of an empty channel is
   * not an error, and must never borrow `provider_error` — "Slack turned that down" would be
   * a false statement about Slack, said to a user.
   */
  empty_channel: 'There are no messages in #general yet.',
  /**
   * Deck row `internal_fault` (ratified 2026-08-16). An engine fault with no
   * `ConnectErrorCode` (`vault_unavailable`, `config_invalid`, `not_implemented`).
   * `{fault}` is an error CODE, never a message, so it can never carry a credential.
   */
  internal_fault: "That didn't go through: {fault}.",
  /**
   * Deck row `browser_open_failed` (ratified 2026-08-16). The engine could not hand the
   * authorize URL to a browser. Previously spoken as `provider_error`, which blamed Slack
   * for a failure that happened entirely on this machine.
   */
  browser_open_failed: "I couldn't open your browser. Nothing was connected.",
} as const;

export type DeckRow = keyof typeof DECK;

/**
 * THE QUARANTINE, now empty — and the test keeps it that way.
 *
 * Every sentence this integration can produce is a deck row above. This constant stays as
 * the place a proposed-but-unratified string would have to sit, in the open, until it is
 * reviewed and promoted into the deck.
 */
export const NOT_IN_DECK = {} as const;

/**
 * WHAT THE CARDS SAY (the visual layer).
 *
 * The spoken layer and the visual layer are the same words wherever a sentence appears: a
 * card renders the DECK row the user is hearing. What lives HERE is the chrome a sentence
 * cannot supply — the labels, chips and headings a Slack-native card needs — held in one
 * frozen table for the same reason the deck is: nothing user-visible is ad-libbed, and
 * `cards.ts` is under the same no-inline-prose rule as `tools.ts`.
 */
export const CARD = {
  /** Every card's identity line. */
  title: 'Slack',
  /** The channel chip's guarded fallback (DESIGN-SPEC §4.5: a specific channel guess is a fabrication). */
  channel: 'Channel',
  /** Header trailing per state — one word, present tense, never a sentence. */
  connected: 'Connected',
  connecting: 'Connecting',
  waiting: 'Waiting for Allow',
  verifying: 'Verifying',
  not_connected: 'Not connected',
  declined: 'Declined',
  expired: 'Expired',
  blocked: 'Blocked',
  discarded: 'Discarded',
  timed_out: 'Timed out',
  refused: 'Refused',
  unavailable: 'Unavailable',
  /** The trust moment: the success card's heading and its two facts. */
  connected_heading: 'Slack connected',
  vault_note: 'Token secured in Keychain.',
  workspace_label: 'Workspace',
  presence: 'Active',
  /** Labels for the reason lines. */
  reason_label: 'Slack said',
  fault_label: 'Fault',
  /** The empty-channel card. */
  empty_title: 'No messages yet',
} as const;

/**
 * The state a tool result is IN — the one field the card layer reads.
 *
 * It is set at the same place the spoken line is chosen (`tools.ts`), so the card can never
 * drift from the sentence: picking the card by sniffing the spoken string would make the UI
 * depend on prose. `message` is the only state with no deck row of its own — it renders
 * `readLine()`, whose sentence is the message itself.
 */
export type SurfaceState = DeckRow | 'message';

/** Spoken prefix for the single-channel read sentence. */
export const READ_PREFIX = 'Last message in #general: ';

/** The channel the demo reads. Resolved by NAME at runtime — never a hard-coded id (D1). */
export const DEMO_CHANNEL = 'general';

function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) => values[key] ?? whole);
}

/** "Connected as Rithvik in VoiceOS HQ." — the workspace clause drops when the probe has none. */
export function connectedLine(handle: string, workspace?: string): string {
  if (workspace === undefined || workspace === '') {
    return fill(DECK.connected, { handle }).replace(' in {workspace}', '');
  }
  return fill(DECK.connected, { handle, workspace });
}

/** "Slack turned that down: not_in_channel. Nothing was connected." */
export function providerErrorLine(reason: string): string {
  return fill(DECK.provider_error, { reason });
}

/** "That didn't go through: vault unavailable." — deck row `internal_fault`. */
export function internalFaultLine(code: string): string {
  return fill(DECK.internal_fault, { fault: code.replace(/_/g, ' ') });
}

/** "Last message in #general: …" */
export function readLine(text: string): string {
  return READ_PREFIX + text;
}

/* ══════════════════════════════ PHASE S — the surface deck ══════════════════════════════ */

/**
 * Surface-deck rows: every sentence the eleven cards can show, written HERE and referenced
 * from `cards.ts`, never minted in the card layer. Kept in their own table, separate from
 * the base `DECK`, so each layer stays reviewable on its own.
 */
export const SDECK = {
  /** Not-connected card (UI-SPEC §3.5). */
  not_connected: "Slack isn't connected on this Mac yet.",
  not_connected_hint: 'Say "connect Slack" to link your workspace.',
  /** In-progress connect card (UI-SPEC §3.6) when the tool passed no spoken line. */
  approve_hint: 'Browser opened. Approve VoiceOS in Slack.',
  /** Disconnect card (UI-SPEC §3.8). `{workspace}` filled only from a provider-named workspace. */
  signed_out: 'Signed out of {workspace}.',
  signed_out_plain: 'Signed out of Slack.',
  tokens_deleted: 'Tokens deleted from this Mac.',
  /** Error cards (UI-SPEC §3.7). `{name}` is the user's own miss, quoted back verbatim. */
  not_found: 'Couldn’t find "{name}".',
  which_one: 'Which one did you mean?',
  slow_down: 'Slack asked us to slow down.',
  missing_detail: 'That command needs one more detail.',
  /** Short refusal note for in-tool provider errors (the Phase-1 row promises "Nothing was connected", which is only true of connect flows). */
  refused_short: 'Slack turned that down.',
} as const;

/**
 * Phase-S chrome — labels and single words for the new surfaces, same rules as `CARD`:
 * never a sentence, never fabricated data. `{n}` / `{m}` templates are filled by the
 * helpers below, so a card cannot compose its own phrasing.
 */
export const SCARD = {
  /** Header trailings. */
  catch_up: 'Catch-up',
  confirm_send: 'Confirm send',
  results: 'Results',
  status: 'Status',
  reminder: 'Reminder',
  disconnected: 'Disconnected',
  not_found: 'Not found',
  rate_limited: 'Rate limited',
  choose: 'Which one?',
  needs_detail: 'Needs a detail',
  /** Date-divider pill words (anything older renders the actual date). */
  today: 'Today',
  yesterday: 'Yesterday',
  /** Labels. */
  until: 'until',
  try_again_label: 'Try again in',
  missing_label: 'Missing',
  dnd_label: 'Notifications snoozed',
  minutes_suffix: 'min',
  /** Candidate-kind words on disambiguation rows. */
  kind_channel: 'Channel',
  kind_person: 'Person',
  kind_dm: 'DM',
  kind_group_dm: 'Group DM',
  /** Overflow templates. */
  more: '+{n} more',
  more_in: '+{n} more in {m} channels',
  more_in_one: '+{n} more in 1 channel',
  /** Phase-D chrome (DESIGN-SPEC §4.4): schedule chip, reply quote, preflight branches. */
  scheduled: 'Scheduled',
  replying_to: 'Replying to',
  needs_check: 'Needs a check',
  which_time: 'Which time?',
  neutral_channel: 'Channel',
} as const;

/**
 * Emoji the cards can draw and the tools can hear (DESIGN-SPEC §2 clarification 1): Slack
 * API names to glyphs, one frozen table used in both directions — `cards.ts` renders
 * name→glyph, `tools-t2.ts` reverse-maps a spoken glyph→name. Glyphs only, no prose; an
 * unknown name renders `:name:` and an unknown glyph blocks rather than guessing.
 */
export const EMOJI_GLYPHS: Readonly<Record<string, string>> = {
  thumbsup: '👍',
  '+1': '👍',
  thumbsdown: '👎',
  heart: '❤️',
  white_check_mark: '✅',
  heavy_check_mark: '✔️',
  x: '❌',
  tada: '🎉',
  eyes: '👀',
  raised_hands: '🙌',
  fire: '🔥',
  joy: '😂',
  rolling_on_the_floor_laughing: '🤣',
  pray: '🙏',
  wave: '👋',
  rocket: '🚀',
  clap: '👏',
  point_up: '☝️',
  point_right: '👉',
  ok_hand: '👌',
  muscle: '💪',
  handshake: '🤝',
  v: '✌️',
  smile: '😄',
  smiley: '😃',
  grinning: '😀',
  laughing: '😆',
  sweat_smile: '😅',
  wink: '😉',
  blush: '😊',
  heart_eyes: '😍',
  sunglasses: '😎',
  thinking_face: '🤔',
  neutral_face: '😐',
  cry: '😢',
  sob: '😭',
  scream: '😱',
  angry: '😠',
  '100': '💯',
  sparkles: '✨',
  star: '⭐',
  zap: '⚡',
  bulb: '💡',
  warning: '⚠️',
  question: '❓',
  exclamation: '❗',
} as const;

/** `+4 more in 2 channels` / `+4 more` — the digest and search overflow line. */
export function moreLine(hidden: number, channels: number): string {
  if (channels <= 0) return fill(SCARD.more, { n: String(hidden) });
  if (channels === 1) return fill(SCARD.more_in_one, { n: String(hidden) });
  return fill(SCARD.more_in, { n: String(hidden), m: String(channels) });
}

/** `Couldn't find "# genral".` — the miss quoted back, never corrected silently. */
export function notFoundLine(name: string): string {
  return fill(SDECK.not_found, { name });
}

/** `Signed out of VoiceOS HQ.` — workspace only when the provider actually named one. */
export function signedOutLine(workspace?: string): string {
  if (workspace === undefined || workspace === '') return SDECK.signed_out_plain;
  return fill(SDECK.signed_out, { workspace });
}

/** Confirmation-composer chrome (Path W widget + shared confirm labels). Frozen strings. */
export const COMPOSER_CHROME = {
  new_message: 'New message',
  reply_in_thread: 'Reply in thread',
  to: 'To:',
  in: 'In',
  message: 'Message',
  cancel_hint: 'Say cancel to discard',
  send: 'Send',
  reply: 'Reply',
} as const;
