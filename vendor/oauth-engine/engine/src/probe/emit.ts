/**
 * Serializing a probe result to its two on-disk artifacts (C-1, SPEC §2).
 *
 * `providers/<name>.json`          — the measured profile the engine consumes.
 * `providers/<name>.evidence.json` — the receipt behind every field.
 *
 * `serialize` is pure (string in, strings out) so a test can assert the exact bytes without
 * touching a filesystem. `writeResult` is the thin I/O wrapper the CLI uses. A final scrub
 * runs over both serialized blobs: the profile and evidence are already built from redacted
 * pieces, but a probe writes files a founder may publish, so credential-shaped runs are
 * scrubbed once more at the boundary — belt and braces, matching redact.ts's own doctrine.
 */

import { redact } from '../redact.ts';
import type { ProbeResult } from './types.ts';

export interface SerializedProbe {
  /** Basename WITHOUT extension, e.g. `slack`. */
  name: string;
  profile_filename: string;
  evidence_filename: string;
  profile_json: string;
  evidence_json: string;
}

export function serialize(result: ProbeResult): SerializedProbe {
  const name = result.profile.name;
  const profile_json = `${redact(JSON.stringify(result.profile, null, 2))}\n`;
  const evidence_json = `${redact(JSON.stringify(result.evidence, null, 2))}\n`;
  return {
    name,
    profile_filename: `${name}.json`,
    evidence_filename: `${name}.evidence.json`,
    profile_json,
    evidence_json,
  };
}
