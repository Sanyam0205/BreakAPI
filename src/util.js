import { randomBytes, createHash } from 'node:crypto';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const newId = (prefix) => `${prefix}_${randomBytes(6).toString('hex')}`;
export const nowIso = () => new Date().toISOString();
export const shortHash = (s) => createHash('sha256').update(s).digest('hex').slice(0, 12);
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const clamp = (n, min, max, fallback) => {
  const v = Number(n);
  return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : fallback;
};

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

export function isLoopbackHost(hostname) {
  const h = String(hostname).replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || /^127\.\d+\.\d+\.\d+$/.test(h);
}

export function mask(value) {
  const v = String(value ?? '');
  return v.length <= 10 ? '••••' : `${v.slice(0, 4)}••••${v.slice(-2)}`;
}

const SECRET_HEADERS = /^(authorization|cookie|set-cookie|x-api-key|api-key|proxy-authorization)$/i;
export function redactHeaders(headers = {}, extraNames = []) {
  const extra = new Set(extraNames.filter(Boolean).map((n) => n.toLowerCase()));
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SECRET_HEADERS.test(k) || extra.has(k.toLowerCase()) ? mask(v) : v;
  }
  return out;
}

export function snippet(text, n = 800) {
  const s = String(text ?? '');
  return s.length > n ? `${s.slice(0, n)}… [${s.length - n} more bytes]` : s;
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

function canonical(body) {
  try {
    return JSON.stringify(sortKeys(JSON.parse(body)));
  } catch {
    return String(body ?? '').trim();
  }
}

/** Rough 0..1 similarity of two response bodies (exact JSON match = 1, else token Jaccard). */
export function similarity(a, b) {
  const x = canonical(a);
  const y = canonical(b);
  if (x === y) return 1;
  const tx = new Set(x.split(/\W+/).filter(Boolean));
  const ty = new Set(y.split(/\W+/).filter(Boolean));
  if (!tx.size && !ty.size) return 1;
  let inter = 0;
  for (const t of tx) if (ty.has(t)) inter++;
  return inter / (tx.size + ty.size - inter);
}
