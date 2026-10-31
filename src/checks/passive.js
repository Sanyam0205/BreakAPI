import { evidence } from './common.js';
import { looksLikeEmail } from '../synthetic.js';

const STACK_TRACE = [
  /\n\s+at [\w.$<>[\] ]+ \(?[^\s()]+:\d+:\d+\)?/,
  /Traceback \(most recent call last\)/,
  /\.java:\d+\)/,
  /System\.[\w.]+Exception/,
  /on line <b>\d+<\/b>/,
  /Exception in thread "/,
];

const NOTE = 'Indicator only: whether this is a defect depends on what the data means. Needs human review.';
const DAY = 86400_000;

function finding(res, f) {
  return { confidence: 'low', endpoint: res.endpoint, evidence: [evidence(res, f.noteless ? undefined : NOTE)], ...f };
}

/** Walks JSON (bounded) and yields [path, key, value, parentObject]. */
function* walk(value, path = '', depth = 0, seen = { n: 0 }) {
  if (depth > 4 || seen.n > 400 || !value || typeof value !== 'object') return;
  const entries = Array.isArray(value) ? value.slice(0, 20).map((v, i) => [String(i), v]) : Object.entries(value);
  for (const [k, v] of entries) {
    seen.n++;
    yield [path ? `${path}.${k}` : k, k, v, value];
    yield* walk(v, path ? `${path}.${k}` : k, depth + 1, seen);
  }
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const time = (v) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v) ? Date.parse(v) : NaN);

/** Read-only analysis of a response the scan already fetched. Returns findings to report. */
export function analyzeResponse(res) {
  const out = [];
  const at = res.endpoint;

  if (STACK_TRACE.some((r) => r.test(res.body))) {
    out.push({
      key: `passive|stacktrace|${at}`,
      title: 'Stack trace exposed in response',
      severity: 'medium',
      confidence: 'high',
      endpoint: at,
      description: 'A response contained a stack trace or debug output.',
      impact: 'Reveals file paths, frameworks, library versions and sometimes queries or secrets that help attackers.',
      remediation: 'Return generic error messages to clients, log details server-side only, and disable debug mode in production.',
      evidence: [evidence(res)],
    });
  }

  // Cookies: session-like cookies need HttpOnly; Secure matters on HTTPS; SameSite limits cross-site use.
  for (const raw of res.setCookies || []) {
    const name = raw.split('=')[0].trim();
    const attrs = raw.toLowerCase();
    const missing = [];
    if (!/;\s*httponly/.test(attrs) && /(sess|auth|token|sid|jwt|login)/i.test(name)) missing.push('HttpOnly');
    if (!/;\s*secure/.test(attrs) && res.url.startsWith('https:')) missing.push('Secure');
    if (!/;\s*samesite=/.test(attrs)) missing.push('SameSite');
    if (!missing.length) continue;
    out.push({
      key: `passive|cookie|${name}|${missing.join('+')}`,
      title: `Cookie "${name}" is missing ${missing.join(', ')}`,
      severity: 'low',
      confidence: 'high',
      endpoint: at,
      description: `The Set-Cookie header for "${name}" lacks ${missing.join(', ')}.`,
      impact: 'Scripts on the page can read the cookie (no HttpOnly), it can travel over plain HTTP (no Secure), or it is sent on cross-site requests (no SameSite).',
      remediation: 'Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies.',
      evidence: [{ request: `${res.method} ${res.url}`, status: res.status, note: `Set-Cookie: ${raw.replace(/=[^;]*/, '=••••')}` }],
    });
  }

  if (res.status < 200 || res.status >= 300 || !/json/i.test(res.contentType)) return out;
  let json;
  try {
    json = JSON.parse(res.body);
  } catch {
    return out;
  }
  const now = Date.now();
  const seenKeys = new Set();
  const add = (kind, f) => {
    const key = `dataquality|${kind}|${at}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);
    out.push(finding(res, { key, ...f }));
  };

  for (const [path, k, v, parent] of walk(json)) {
    if (/e-?mail/i.test(k) && typeof v === 'string' && v && !looksLikeEmail(v)) {
      add('email', { title: 'Malformed email address in data', severity: 'low', description: `"${path}" holds "${v}", which is not a well-formed address.`, impact: 'Verification, notifications and password reset will fail for this record, and it suggests missing server-side validation.', remediation: 'Validate email on write, and clean up existing records.' });
    }
    const n = num(v);
    if (n !== null && /^(age)$/i.test(k) && (n < 0 || n > 130)) {
      add('age', { title: `Implausible age in data (${n})`, severity: 'low', description: `"${path}" is ${n}.`, impact: 'Impossible values usually mean missing range validation on write.', remediation: 'Validate ranges on the server.' });
    }
    if (n !== null && /^(quantity|qty|stock|count)$/i.test(k) && n < 0) {
      add('negative', { title: `Negative ${k} in data`, severity: 'low', description: `"${path}" is ${n}.`, impact: 'Negative counts indicate missing validation or broken business rules.', remediation: 'Validate on write and add database constraints.' });
    }
    if (n !== null && /^balance$/i.test(k) && n < 0) {
      add('balance', { title: 'Negative balance in data', severity: 'info', description: `"${path}" is ${n}. This can be legitimate (for example an overdraft).`, impact: 'May show a missing check on spending or refunds.', remediation: 'Confirm that a negative balance is allowed by your rules.' });
    }
    if (/^(birth_?date|dob|birthday)$/i.test(k)) {
      const t = time(v);
      if (!Number.isNaN(t) && (t < Date.parse('1900-01-01') || t > now)) add('birthdate', { title: 'Implausible birth date in data', severity: 'low', description: `"${path}" is ${v}.`, impact: 'Impossible dates usually mean missing validation on write.', remediation: 'Validate date ranges on the server.' });
    }
    if (/^created_?at$/i.test(k)) {
      const created = time(v);
      const updatedKey = Object.keys(parent).find((x) => /^updated_?at$/i.test(x));
      const updated = updatedKey ? time(parent[updatedKey]) : NaN;
      if (!Number.isNaN(created) && created > now + DAY) add('future', { title: 'Record created in the future', severity: 'low', description: `"${path}" is ${v}.`, impact: 'Suggests clock problems or client-supplied timestamps being trusted.', remediation: 'Set timestamps on the server.' });
      if (!Number.isNaN(created) && !Number.isNaN(updated) && updated < created) add('order', { title: 'updatedAt is earlier than createdAt', severity: 'low', description: `"${path}" is ${v} but ${updatedKey} is ${parent[updatedKey]}.`, impact: 'Inconsistent timestamps point to client-controlled fields or broken update logic.', remediation: 'Maintain timestamps on the server only.' });
    }
    if (/^(email_?verified|verified|is_?verified)$/i.test(k) && v === false && /^(admin|staff|superuser|owner)$/i.test(String(parent.role ?? ''))) {
      add('unverified-admin', { title: 'Unverified account holds a privileged role', severity: 'low', description: `"${path}" is false while role is "${parent.role}".`, impact: 'Privileged accounts should not exist without a verified identity.', remediation: 'Require verification before granting privileges.' });
    }
  }
  return out;
}
