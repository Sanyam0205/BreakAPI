import { buildRequest, valuesFor, is2xx } from './common.js';
import { isEmailField, isPasswordField } from '../synthetic.js';

const WRITE_METHODS = ['POST', 'PUT', 'PATCH'];

/** Endpoints a person opted in to synthetic writes, whose method the authorization allows. */
export function syntheticTargets(client, endpoints, kinds) {
  return endpoints.filter((e) => WRITE_METHODS.includes(e.method) && e.syntheticWrites && client.methodAllowed(e.method) && (!kinds || kinds.includes(e.kind)));
}

/** A regular (non-admin) test account is the one that acts; admins are never used for mutated payloads. */
export const actingAccount = (ep, accounts) => (ep.requiresAuth ? accounts.find((a) => a.role !== 'admin') : undefined);

/**
 * Request for the account's *own* object: path parameters must come from the account's resource IDs.
 * Returns null when they cannot, so a synthetic write is never aimed at an object that might not be a test object.
 */
export function ownRequest(ep, account) {
  const pathParams = ep.params.filter((p) => p.in === 'path');
  if (pathParams.some((p) => account?.resourceIds?.[p.name] == null)) return null;
  return buildRequest(ep, valuesFor(ep, account));
}

/** The endpoint's example body with unique synthetic values in identity-like fields, then overrides. */
export function cloneBody(ep, syn, overrides = {}) {
  const body = structuredClone(ep.bodyExample && typeof ep.bodyExample === 'object' ? ep.bodyExample : {});
  for (const k of Object.keys(body)) {
    if (isEmailField(k)) body[k] = syn.email();
    else if (isPasswordField(k)) body[k] = syn.password();
    else if (/^(name|username|user_?name|title)$/i.test(k)) body[k] = syn.name();
  }
  return { ...body, ...overrides };
}

export function parseJson(res) {
  try {
    return JSON.parse(res.body);
  } catch {
    return null;
  }
}

/**
 * Did the server take the value we sent for `field`?
 * 'echoed' (it came back unchanged), 'overridden' (it came back different: the server decided),
 * 'unknown' (2xx but the field is not in the response) or 'rejected'.
 * Only 'echoed' and 'unknown' count as findings, so an API that ignores a bad field is not flagged.
 */
export function acceptance(res, field, sent) {
  if (!is2xx(res)) return 'rejected';
  const hit = findKey(parseJson(res), [field]);
  if (!hit) return 'unknown';
  return String(hit.value) === String(sent) ? 'echoed' : 'overridden';
}

export const accepted = (a) => a === 'echoed' || a === 'unknown';
export const confidenceOf = (a, whenEchoed = 'high') => (a === 'echoed' ? whenEchoed : 'low');

/** Finds a key (case-insensitive) in an object or one level of nesting, e.g. { user: { role } }. */
export function findKey(obj, names, depth = 2) {
  if (!obj || typeof obj !== 'object' || depth < 0) return undefined;
  const wanted = names.map((n) => n.toLowerCase());
  for (const [k, v] of Object.entries(obj)) if (wanted.includes(k.toLowerCase())) return { key: k, value: v };
  for (const v of Object.values(obj)) {
    const hit = v && typeof v === 'object' ? findKey(v, names, depth - 1) : undefined;
    if (hit) return hit;
  }
  return undefined;
}
