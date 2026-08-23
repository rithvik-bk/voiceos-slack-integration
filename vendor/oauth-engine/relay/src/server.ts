/**
 * The relay's HTTP surface — node's built-in `http`, zero dependencies (SPEC §5).
 *
 * It wires two routes to the two handlers and nothing else. There is no session store, no
 * database handle, no disk write anywhere in this file: the server holds a keystore (RAM) and
 * a logger (credential-free), and every request is served from the handler's return value and
 * then forgotten. Statelessness is not a feature toggled on; it is the absence of any code
 * that would remember.
 *
 *   POST /v1/assertion   B2a — sign a client assertion, return only the signature
 *   POST /v1/exchange    B2b — forward one exchange, return the sealed token
 *   GET  /healthz        liveness; returns configured provider NAMES only, never secrets
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { forwardExchange, signAssertion, type HandlerDeps } from './handlers.ts';
import { RelayKeyStore } from './keystore.ts';
import { RelayLog } from './log.ts';
import { RelayError, type AssertionRequest, type ExchangeRequest } from './types.ts';

/** A request body larger than this is a mistake or an attack, not a token request. */
const MAX_BODY_BYTES = 16 * 1024;

export interface RelayServerOptions {
  keystore: RelayKeyStore;
  log?: RelayLog;
  fetchImpl?: typeof fetch;
}

export function createRelay(options: RelayServerOptions): Server {
  const deps: HandlerDeps = {
    keystore: options.keystore,
    log: options.log ?? new RelayLog(),
    ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
  };

  return createServer((req, res) => {
    void route(req, res, deps).catch((err) => {
      // Last-resort guard. `writeError` never echoes provider text or request bodies.
      writeError(res, err);
    });
  });
}

async function route(req: IncomingMessage, res: ServerResponse, deps: HandlerDeps): Promise<void> {
  const { method, url } = req;

  if (method === 'GET' && url === '/healthz') {
    return writeJson(res, 200, { ok: true, providers: deps.keystore.providers() });
  }

  if (method !== 'POST') {
    return writeError(res, new RelayError('bad_request', 'only POST is accepted on this route', 405));
  }

  if (url === '/v1/assertion') {
    const request = (await readJson(req)) as AssertionRequest;
    return writeJson(res, 200, signAssertion(request, deps));
  }

  if (url === '/v1/exchange') {
    const request = (await readJson(req)) as ExchangeRequest;
    return writeJson(res, 200, await forwardExchange(request, deps));
  }

  return writeError(res, new RelayError('bad_request', 'no such route', 404));
}

/** Read a bounded JSON body. Over the cap → reject; malformed → reject. Never logged. */
function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new RelayError('bad_request', 'request body too large', 413));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new RelayError('bad_request', 'request body is not valid JSON'));
      }
    });
    req.on('error', () => reject(new RelayError('bad_request', 'request stream error')));
  });
}

function writeJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(body);
}

/**
 * Map an error to a response. Only the typed code and its safe message are surfaced — a
 * RelayError's message is written by this codebase, never by a provider, so it cannot carry
 * upstream credential text. An unknown throwable degrades to a generic 500.
 */
function writeError(res: ServerResponse, err: unknown): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  if (err instanceof RelayError) {
    return writeJson(res, err.httpStatus, { error: err.code, message: err.message });
  }
  return writeJson(res, 500, { error: 'internal', message: 'relay error' });
}

/* ─────────────────────────────── stand-alone entrypoint ─────────────────────────────── */

// `node src/server.ts` boots a relay from the environment. Guarded so importing this module
// (tests, an embedder) does not start a listener.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.RELAY_PORT ?? 8787);
  const server = createRelay({ keystore: RelayKeyStore.fromEnv() });
  server.listen(port, () => {
    // The one startup line. Names, never secrets.
    process.stdout.write(`handshake-relay listening on :${port}\n`);
  });
}
