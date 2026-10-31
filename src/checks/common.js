import { snippet, redactHeaders } from '../util.js';

export const is2xx = (r) => !!r && !r.skipped && r.status >= 200 && r.status < 300;

const mediaKind = (r) => (/json/i.test(r?.contentType) ? 'json' : /html/i.test(r?.contentType) ? 'html' : 'other');

/** Guards against SPA catch-alls: a 200 HTML page is not the same resource as a JSON API response. */
export const sameKind = (a, b) => !a || !is2xx(a) || mediaKind(a) === mediaKind(b);

export const label = (ep) => `${ep.method} ${ep.path}`;

function sampleValue(p) {
  return p.type === 'integer' || p.type === 'number' || /id$/i.test(p.name) ? '1' : 'test';
}

/** Values for path params and required query params, preferring the account's own resource IDs. */
export function valuesFor(ep, account, overrides = {}) {
  const v = {};
  for (const p of ep.params) {
    if (p.in !== 'path' && !p.required) continue;
    v[p.name] = String(overrides[p.name] ?? account?.resourceIds?.[p.name] ?? p.example ?? sampleValue(p));
  }
  return v;
}

export function buildRequest(ep, values) {
  let path = ep.path;
  const query = {};
  for (const p of ep.params) {
    if (!(p.name in values)) continue;
    if (p.in === 'path') path = path.replaceAll(`{${p.name}}`, encodeURIComponent(values[p.name]));
    else query[p.name] = values[p.name];
  }
  return { method: ep.method, path, query, body: ep.bodyExample, endpoint: label(ep) };
}

export function evidence(res, note) {
  if (!res) return { note };
  return {
    request: `${res.method} ${res.url}`,
    requestHeaders: res.requestHeaders,
    requestBody: res.requestBody ? snippet(res.requestBody, 600) : undefined,
    status: res.status,
    responseHeaders: redactHeaders(res.headers),
    body: snippet(res.body),
    note,
  };
}
