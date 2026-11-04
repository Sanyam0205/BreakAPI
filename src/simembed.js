// Runs the simulation backend (the separate breakapi-sim repo, checked out in a folder) inside this
// process, for hosts that can run only one app (a single Replit project).
//
// The sim listens on a random loopback port and is never reachable directly. Two things use it:
//  - the lab's control calls go straight to that loopback port, with a key generated at every boot;
//  - visitors and the scanner reach sandboxes through breakAPI at /sim/s/<id>/…, which forwards only
//    those paths. /sim/_control and the rest of the sim's surface are not forwarded.
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const SIM_PREFIX = '/sim';
// The root notice and sandbox traffic. Nothing else of the sim is public.
const FORWARDED = /^\/sim(?:\/|\/s\/[A-Za-z0-9_-]{1,40}(?:\/.*)?)?$/;
const PASS_HEADERS = ['authorization', 'origin', 'content-type', 'content-length', 'accept', 'user-agent', 'x-breakapi-scan', 'cookie', 'if-none-match'];
const UPSTREAM_TIMEOUT_MS = 15_000;

/**
 * dir:        the breakapi-sim checkout (contains src/server.js)
 * publicBase: where sandboxes are reached from outside, e.g. https://app.example.com/sim
 */
export async function startEmbeddedSim({ dir, publicBase, log = console }) {
  const entry = join(resolve(dir), 'src', 'server.js');
  if (!existsSync(entry)) {
    throw new Error(`BREAKAPI_SIM_EMBED_DIR does not contain src/server.js (looked in ${resolve(dir)}). Clone the breakapi-sim repo there.`);
  }
  const { createSimServer } = await import(pathToFileURL(entry).href);
  if (typeof createSimServer !== 'function') throw new Error('The breakapi-sim checkout does not export createSimServer; update it.');

  const key = randomBytes(24).toString('base64url');
  const server = createSimServer({ controlKey: key, publicUrl: publicBase, log });
  await new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(0, '127.0.0.1', ok);
  });
  const port = server.address().port;

  /** Forwards one request to the loopback sim, or answers 404 for anything that is not sandbox traffic. */
  const forward = (req, res, url) => {
    const json = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    if (!FORWARDED.test(url.pathname)) return json(404, { error: { code: 'not_found', message: 'Not found.' } });
    const headers = {};
    for (const h of PASS_HEADERS) if (req.headers[h] !== undefined) headers[h] = req.headers[h];
    const upstream = http.request({
      host: '127.0.0.1',
      port,
      method: req.method,
      path: (url.pathname.slice(SIM_PREFIX.length) || '/') + url.search,
      headers,
      timeout: UPSTREAM_TIMEOUT_MS,
    }, (up) => {
      res.writeHead(up.statusCode, up.headers);
      up.pipe(res);
    });
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', () => json(502, { error: { code: 'bad_gateway', message: 'The simulation is not responding.' } }));
    req.pipe(upstream);
  };

  return {
    url: `http://127.0.0.1:${port}`,
    key,
    forward,
    close: () => new Promise((ok) => {
      server.closeAllConnections?.();
      server.close(() => ok());
    }),
  };
}
