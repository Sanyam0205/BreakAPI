import http from 'node:http';
import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import { isIP } from 'node:net';
import { getConfig } from './config.js';

const MAX_BODY = 256 * 1024;

const v4 = (ip) => ip.split('.').map(Number);

/** Classifies an IP literal: loopback, private, linklocal, metadata, unspecified or public. */
export function classifyAddress(ip0) {
  let ip = String(ip0).replace(/^\[|\]$/g, '').toLowerCase();
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) ip = mapped[1];
  if (isIP(ip) === 4) {
    const [a, b] = v4(ip);
    if (ip === '169.254.169.254' || ip === '100.100.100.200') return 'metadata';
    if (a === 127) return 'loopback';
    if (a === 0) return 'unspecified';
    if (a === 169 && b === 254) return 'linklocal';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return 'private';
    return 'public';
  }
  if (isIP(ip) === 6) {
    if (ip === '::1') return 'loopback';
    if (ip === '::') return 'unspecified';
    if (ip === 'fd00:ec2::254') return 'metadata';
    if (/^fe[89ab][0-9a-f]:/.test(ip)) return 'linklocal';
    if (/^f[cd][0-9a-f]{2}:/.test(ip)) return 'private';
    return 'public';
  }
  return 'invalid';
}

/** Why this address may not be contacted under the current configuration, or null if it may. */
export function addressRefusal(ip, config = getConfig()) {
  const kind = classifyAddress(ip);
  if (kind === 'metadata' || kind === 'linklocal') return `${ip} is a link-local or cloud-metadata address, which breakAPI never contacts.`;
  if ((kind === 'loopback' || kind === 'unspecified') && !config.allowLocalTargets) return `${ip} is on this server itself; local targets are disabled here (BREAKAPI_ALLOW_LOCAL_TARGETS).`;
  if (kind === 'private' && !config.allowPrivateTargets) return `${ip} is a private-network address; private targets are disabled here (BREAKAPI_ALLOW_PRIVATE_TARGETS).`;
  if (kind === 'invalid') return `${ip} is not a valid address.`;
  return null;
}

/**
 * A DNS lookup for http(s).request that refuses forbidden addresses. Because the check runs
 * inside the connection's own lookup, the address that was checked is the address connected to:
 * a DNS answer cannot change between the check and the request (no rebinding window).
 */
export function guardedLookup(config = getConfig()) {
  return (hostname, options, callback) => {
    const cb = typeof options === 'function' ? options : callback;
    const opts = typeof options === 'object' ? options : {};
    dnsLookup(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) return cb(err);
      const list = Array.isArray(addresses) ? addresses : [{ address: addresses, family: opts.family || 4 }];
      for (const a of list) {
        const why = addressRefusal(a.address, config);
        if (why) {
          const e = new Error(why);
          e.code = 'EBREAKAPI_BLOCKED';
          return cb(e);
        }
      }
      if (opts.all) return cb(null, list);
      return cb(null, list[0].address, list[0].family);
    });
  };
}

/**
 * Minimal fetch for scanning: no redirects followed, bounded body, timeout, guarded DNS.
 * Resolves { status, headers, setCookies, body } or rejects with { code } on network errors.
 */
export function safeFetch(url0, { method = 'GET', headers = {}, body, timeoutMs = 10000, maxBody = MAX_BODY, config = getConfig() } = {}) {
  const url = new URL(url0);
  const lib = url.protocol === 'https:' ? https : http;
  // Node skips the custom lookup for IP literals, so check those here.
  const literal = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(literal)) {
    const why = addressRefusal(literal, config);
    if (why) return Promise.reject(Object.assign(new Error(why), { code: 'EBREAKAPI_BLOCKED' }));
  }
  return new Promise((resolve, reject) => {
    const req = lib.request(url, {
      method,
      headers: { ...headers, ...(body !== undefined ? { 'content-length': Buffer.byteLength(body) } : {}) },
      lookup: guardedLookup(config),
      timeout: timeoutMs,
      agent: false,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        if (size >= maxBody) return;
        chunks.push(c);
        size += c.length;
        if (size >= maxBody) res.destroy();
      });
      const done = () => {
        const out = {};
        for (const [k, v] of Object.entries(res.headers)) if (k !== 'set-cookie') out[k] = Array.isArray(v) ? v.join(', ') : v;
        resolve({ status: res.statusCode, headers: out, setCookies: res.headers['set-cookie'] || [], body: Buffer.concat(chunks).toString('utf8').slice(0, maxBody) });
      };
      res.on('end', done);
      res.on('close', done);
      res.on('error', done);
    });
    req.on('timeout', () => {
      const e = new Error('timeout');
      e.code = 'TIMEOUT';
      req.destroy(e);
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Checks a host[:port] entry from an authorization before any request: literal IPs are checked directly. */
export function hostRefusal(entry, config = getConfig()) {
  let hostname;
  try {
    hostname = new URL(`http://${entry}`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return `"${entry}" is not a valid host.`;
  }
  if (isIP(hostname)) return addressRefusal(hostname, config);
  if (!config.allowLocalTargets && (hostname === 'localhost' || hostname.endsWith('.localhost'))) {
    return `${entry} is on this server itself; local targets are disabled here (BREAKAPI_ALLOW_LOCAL_TARGETS).`;
  }
  return null;
}
