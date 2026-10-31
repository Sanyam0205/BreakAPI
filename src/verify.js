import { isIP } from 'node:net';
import { resolveTxt } from 'node:dns/promises';
import { classifyAddress, safeFetch, hostRefusal } from './netguard.js';

const WELL_KNOWN = '/.well-known/breakapi-verification.txt';

export function blockedAddress(ip) {
  return ['metadata', 'linklocal'].includes(classifyAddress(ip));
}

/**
 * Proves a token can be published at the target, by well-known file or DNS TXT record.
 * Returns { ok: true, method } or { ok: false, error }. This is evidence of control at one
 * moment, not proof of ownership (see AUTH_LIMITATIONS).
 */
export async function challengeHost({ entry, scheme = 'https', token, txtImpl = resolveTxt }) {
  let url;
  try {
    url = new URL(`${scheme}://${entry}`);
  } catch {
    return { ok: false, error: `"${entry}" is not a valid host.` };
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const refusal = hostRefusal(entry);
  if (refusal) return { ok: false, error: refusal };

  const where = [];
  try {
    // Same guarded client as scans: link-local, metadata and (per configuration) local or private addresses are refused.
    const r = await safeFetch(new URL(WELL_KNOWN, url.origin), { timeoutMs: 8000, maxBody: 4096, headers: { 'user-agent': 'breakAPI/0.1 (ownership verification)' } });
    const text = r.status >= 200 && r.status < 300 ? r.body : '';
    if (text.split(/\r?\n/).some((line) => line.trim() === token)) return { ok: true, method: 'well-known file' };
    where.push(`${url.origin}${WELL_KNOWN}`);
  } catch (err) {
    if (err.code === 'EBREAKAPI_BLOCKED') return { ok: false, error: err.message };
    where.push(`${url.origin}${WELL_KNOWN} (unreachable)`);
  }
  if (!isIP(hostname)) {
    try {
      const records = await txtImpl(`_breakapi.${hostname}`);
      if (records.some((r) => r.join('').trim() === token)) return { ok: true, method: 'DNS TXT record' };
    } catch {
      /* no record */
    }
    where.push(`a TXT record on _breakapi.${hostname}`);
  }
  return { ok: false, error: `Token not found at ${where.join(' or ')}.` };
}
