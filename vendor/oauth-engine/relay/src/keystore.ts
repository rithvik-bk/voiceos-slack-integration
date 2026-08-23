/**
 * The relay's key material, held in memory only.
 *
 * The relay holds exactly two kinds of secret, per provider:
 *   - B2a: an asymmetric PRIVATE KEY, used to sign client assertions. The provider registered
 *     the matching public key; the private key here is what makes the assertion trustworthy.
 *   - B2b: a shared CLIENT SECRET, used to authenticate the one token exchange the relay
 *     performs on the device's behalf.
 *
 * What the relay does NOT hold, ever: a user token, a refresh token, an authorization code, a
 * PKCE verifier. Those are either never seen (B2a) or seen only in flight for one exchange and
 * never written down (B2b). This class is the whole of the relay's persistent secret surface,
 * and it is RAM, not disk.
 *
 * Secrets arrive by ENVIRONMENT, which is how a self-hosted relay is configured without a
 * secret ever touching argv (visible in `ps`), a temp file, or this repo. `fromEnv` reads
 * once at boot and keeps the parsed KeyObjects in a closed Map. There is no getter that
 * returns raw secret bytes for logging, and `toString`/`toJSON` are overridden to refuse to
 * serialize — a keystore can never be the thing that leaks into an event log.
 */

import { createPrivateKey, type KeyObject } from 'node:crypto';

import type { JwtAlg } from './jwt.ts';
import { RelayError } from './types.ts';

export interface SigningKey {
  privateKey: KeyObject;
  alg: JwtAlg;
  /** iss/sub of every assertion — pinned in config, never taken from the request. */
  clientId: string;
  /** aud of every assertion — the provider token endpoint, pinned in config. */
  audience: string;
  kid?: string;
}

export interface ClientSecret {
  clientId: string;
  clientSecret: string;
  /** The ONLY URL the relay will POST this secret to — pinned in config, never from a request. */
  tokenUrl: string;
}

export class RelayKeyStore {
  #signing = new Map<string, SigningKey>();
  #secrets = new Map<string, ClientSecret>();

  /** Register a B2a signing key for a provider. */
  addSigningKey(provider: string, key: SigningKey): this {
    this.#signing.set(provider, key);
    return this;
  }

  /** Register a B2b client secret for a provider. */
  addClientSecret(provider: string, secret: ClientSecret): this {
    this.#secrets.set(provider, secret);
    return this;
  }

  /** The B2a signing key for a provider, or a typed error the server maps to 404. */
  signingKey(provider: string): SigningKey {
    const key = this.#signing.get(provider);
    if (key === undefined) {
      throw new RelayError('unknown_provider', `no signing key configured for '${provider}'`, 404);
    }
    return key;
  }

  /** The B2b client secret for a provider, or a typed error the server maps to 404. */
  clientSecret(provider: string): ClientSecret {
    const secret = this.#secrets.get(provider);
    if (secret === undefined) {
      throw new RelayError('unknown_provider', `no client secret configured for '${provider}'`, 404);
    }
    return secret;
  }

  /** Which providers can use B2a / B2b. Names only — never secret material. */
  providers(): { signing: string[]; forwarding: string[] } {
    return { signing: [...this.#signing.keys()], forwarding: [...this.#secrets.keys()] };
  }

  /** A keystore must never serialize into a log line. Both refuse. */
  toString(): string {
    return '[RelayKeyStore redacted]';
  }
  toJSON(): string {
    return '[RelayKeyStore redacted]';
  }

  /**
   * Build a keystore from the environment. Convention:
   *   RELAY_SIGNING_KEY__<PROVIDER>       PEM of the private key (B2a)
   *   RELAY_SIGNING_ALG__<PROVIDER>       'ES256' | 'RS256' (default inferred from key type)
   *   RELAY_SIGNING_CLIENT_ID__<PROVIDER> the app client id → assertion iss/sub (B2a)
   *   RELAY_SIGNING_AUDIENCE__<PROVIDER>  the token endpoint → assertion aud (B2a)
   *   RELAY_CLIENT_ID__<PROVIDER>         client id      (B2b)
   *   RELAY_CLIENT_SECRET__<PROVIDER>     client secret  (B2b)
   *   RELAY_TOKEN_URL__<PROVIDER>         the one URL the secret may be POSTed to (B2b)
   * Provider tokens in var names are UPPER_SNAKE; the map key lowercases back.
   */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): RelayKeyStore {
    const store = new RelayKeyStore();

    for (const [name, value] of Object.entries(env)) {
      if (value === undefined || value.length === 0) continue;

      const signing = name.match(/^RELAY_SIGNING_KEY__(.+)$/);
      if (signing?.[1] !== undefined) {
        const provider = signing[1].toLowerCase();
        let privateKey: KeyObject;
        try {
          privateKey = createPrivateKey(value);
        } catch {
          throw new RelayError('config_invalid', `RELAY_SIGNING_KEY__${signing[1]} is not a valid private key`, 500);
        }
        const declared = env[`RELAY_SIGNING_ALG__${signing[1]}`];
        const alg = normalizeAlg(declared, privateKey);
        const clientId = env[`RELAY_SIGNING_CLIENT_ID__${signing[1]}`];
        const audience = env[`RELAY_SIGNING_AUDIENCE__${signing[1]}`];
        if (clientId === undefined || clientId.length === 0 || audience === undefined || audience.length === 0) {
          throw new RelayError(
            'config_invalid',
            `RELAY_SIGNING_KEY__${signing[1]} needs RELAY_SIGNING_CLIENT_ID__${signing[1]} and RELAY_SIGNING_AUDIENCE__${signing[1]}`,
            500,
          );
        }
        store.addSigningKey(provider, { privateKey, alg, clientId, audience });
        continue;
      }

      const clientId = name.match(/^RELAY_CLIENT_ID__(.+)$/);
      if (clientId?.[1] !== undefined) {
        const provider = clientId[1].toLowerCase();
        const secret = env[`RELAY_CLIENT_SECRET__${clientId[1]}`];
        const tokenUrl = env[`RELAY_TOKEN_URL__${clientId[1]}`];
        if (secret === undefined || secret.length === 0) {
          throw new RelayError('config_invalid', `RELAY_CLIENT_ID__${clientId[1]} has no matching RELAY_CLIENT_SECRET`, 500);
        }
        if (tokenUrl === undefined || tokenUrl.length === 0) {
          throw new RelayError('config_invalid', `RELAY_CLIENT_ID__${clientId[1]} has no matching RELAY_TOKEN_URL`, 500);
        }
        store.addClientSecret(provider, { clientId: value, clientSecret: secret, tokenUrl });
      }
    }

    return store;
  }
}

function normalizeAlg(declared: string | undefined, key: KeyObject): JwtAlg {
  if (declared === 'ES256' || declared === 'RS256') return declared;
  // Infer from the key type: EC → ES256, RSA → RS256. An unexpected type is a config error.
  const type = key.asymmetricKeyType;
  if (type === 'ec') return 'ES256';
  if (type === 'rsa') return 'RS256';
  throw new RelayError('config_invalid', `unsupported signing key type '${String(type)}' — use EC (ES256) or RSA (RS256)`, 500);
}
