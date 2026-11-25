import { decrypt } from './crypto.js';
import { GuardedClient, ScanHalt } from './client.js';
import { preflight } from './scope.js';
import { newId, nowIso, mask, SEVERITIES } from './util.js';
import config from './checks/config.js';
import exposure from './checks/exposure.js';
import authn from './checks/authn.js';
import authz from './checks/authz.js';
import input from './checks/input.js';
import validation from './checks/validation.js';
import identity from './checks/identity.js';
import logic from './checks/logic.js';
import ratelimit from './checks/ratelimit.js';
import { analyzeResponse } from './checks/passive.js';

// Rate limiting runs last so its burst cannot starve the other checks of budget.
const CHECKS = [config, exposure, authn, authz, input, validation, identity, logic, ratelimit];
const MAX_LOG = 2000;


/** scanId -> { paused, stopReason, userStopped } for scans running in this process. */
export const running = new Map();

export function audit(project, event, detail = {}) {
  project.audit ??= [];
  project.audit.push({ at: nowIso(), event, ...detail });
}

/** Every form a target could echo a secret in: raw, URL-encoded, base64 (padded, bare, URL-safe) and JSON-escaped. */
function secretForms(s) {
  const b64 = Buffer.from(s).toString('base64');
  return [s, encodeURIComponent(s), encodeURI(s), b64, b64.replace(/=+$/, ''), Buffer.from(s).toString('base64url'), JSON.stringify(s).slice(1, -1)];
}

/**
 * Returns a function that replaces every known test-account secret in the strings of a value
 * (deeply) with its mask, in each form from `secretForms`, so a target that echoes a credential
 * back cannot leak it into stored findings or the log. Secrets under 8 characters are skipped:
 * they would mangle ordinary text. Only secrets we hold are known, and only whole-secret
 * encodings are caught (not a base64 of a string that merely contains the secret).
 */
export function makeScrubber(accounts) {
  const secrets = new Set();
  for (const a of accounts) {
    const s = String(a.secret ?? '');
    secrets.add(s);
    if (a.authType === 'cookie') for (const part of s.split(';')) secrets.add(part.slice(part.indexOf('=') + 1).trim());
  }
  const pairs = [];
  for (const s of secrets) if (s.length >= 8) for (const form of new Set(secretForms(s))) pairs.push([form, mask(s)]);
  pairs.sort((x, y) => y[0].length - x[0].length);
  const walk = (v) => {
    if (typeof v === 'string') return pairs.reduce((t, [form, m]) => t.replaceAll(form, m), v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk;
}

function pushLog(scan, entry) {
  scan.log.push(entry);
  if (scan.log.length > MAX_LOG) scan.log.splice(0, scan.log.length - MAX_LOG);
}

export function createScan(store, project, { previousScanId } = {}) {
  const scan = {
    id: newId('scan'),
    projectId: project.id,
    status: 'queued',
    createdAt: nowIso(),
    previousScanId: previousScanId || null,
    requestsSent: 0,
    checks: [],
    findings: [],
    log: [],
  };
  store.data.scans[scan.id] = scan;
  return scan;
}

function compare(prev, cur) {
  const completed = (s) => new Set(s.checks.filter((c) => c.status === 'done').map((c) => c.id));
  const prevDone = completed(prev);
  const curDone = completed(cur);
  const curKeys = new Set(cur.findings.map((f) => f.key));
  const prevKeys = new Set(prev.findings.map((f) => f.key));
  const brief = (f) => ({ key: f.key, title: f.title, endpoint: f.endpoint, severity: f.severity });
  const gone = prev.findings.filter((f) => !curKeys.has(f.key));
  return {
    previousScanId: prev.id,
    fixed: gone.filter((f) => prevDone.has(f.check) && curDone.has(f.check)).map(brief),
    unverified: gone.filter((f) => !(prevDone.has(f.check) && curDone.has(f.check))).map(brief),
    stillOpen: cur.findings.filter((f) => prevKeys.has(f.key)).map(brief),
    new: cur.findings.filter((f) => !prevKeys.has(f.key)).map(brief),
  };
}

/** `checks` defaults to every check category; tests pass their own list. */
export async function runScan({ store, key, checks = CHECKS }, scanId) {
  const scan = store.data.scans[scanId];
  const project = store.data.projects[scan.projectId];
  const control = { paused: false, stopReason: null, userStopped: false };
  running.set(scanId, control);

  const problems = preflight(project);
  if (problems.length) {
    Object.assign(scan, { status: 'blocked', problems, finishedAt: nowIso() });
    audit(project, 'scan.blocked', { scanId, problems });
    running.delete(scanId);
    store.saveNow();
    return scan;
  }

  const allowed = new Set(project.authorization.allowedTests);
  Object.assign(scan, {
    status: 'running',
    startedAt: nowIso(),
    authorizationSnapshot: structuredClone(project.authorization),
    controlsSnapshot: structuredClone(project.controls),
    targetSnapshot: { baseUrl: project.target.baseUrl, endpointCount: project.target.endpoints.filter((e) => e.enabled).length },
    checks: CHECKS.map((c) => ({ id: c.id, status: allowed.has(c.id) ? 'pending' : 'not authorized' })),
  });
  audit(project, 'scan.started', { scanId });
  store.saveNow();

  const accounts = (project.accounts || []).filter((a) => a.secretEnc).map((a) => ({ ...a, secret: decrypt(key, a.secretEnc) }));
  const scrub = makeScrubber(accounts);
  const endpoints = project.target.endpoints.filter((e) => e.enabled);
  const keys = new Set();
  let current = 'passive';

  const report = (f) => {
    if (keys.has(f.key)) return;
    keys.add(f.key);
    scan.findings.push(scrub({ id: newId('f'), confidence: 'high', check: current, at: nowIso(), ...f }));
    store.save();
  };

  const passive = (res) => {
    const prev = current;
    current = 'passive';
    for (const f of analyzeResponse(res)) report(f);
    current = prev;
  };

  const client = new GuardedClient({ project, scan, control, onLog: (e) => pushLog(scan, scrub(e)), onResponse: passive });
  const ctx = { client, project, scan, endpoints, accounts, report, log: (note) => pushLog(scan, scrub({ at: nowIso(), note })) };
  if (!accounts.length) ctx.log('No test account credentials available — authenticated checks will be limited.');

  try {
    for (const check of checks) {
      const entry = scan.checks.find((c) => c.id === check.id);
      if (entry.status === 'not authorized') continue;
      current = check.id;
      entry.status = 'running';
      entry.startedAt = nowIso();
      store.save();
      try {
        await check.run(ctx);
        entry.status = 'done';
      } catch (err) {
        if (err instanceof ScanHalt) throw err;
        // One broken check must not cost the user every later check; retests treat it as not re-verified.
        entry.status = 'failed';
        entry.error = err.message;
        ctx.log(`Check ${check.id} failed: ${err.stack || err.message}`);
      }
      entry.finishedAt = nowIso();
    }
    scan.checks.push({ id: 'passive', status: 'done' });
    scan.status = 'completed';
  } catch (err) {
    for (const c of scan.checks) if (c.status === 'running' || c.status === 'pending') c.status = 'incomplete';
    if (err instanceof ScanHalt) {
      scan.status = control.userStopped ? 'stopped' : 'halted';
      scan.stopReason = err.reason;
    } else {
      scan.status = 'failed';
      scan.error = err.message;
      ctx.log(`Internal error: ${err.stack || err.message}`);
    }
  } finally {
    scan.finishedAt = nowIso();
    scan.findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
    const prev = scan.previousScanId && store.data.scans[scan.previousScanId];
    if (prev) scan.comparison = compare(prev, scan);
    audit(project, `scan.${scan.status}`, { scanId, requestsSent: scan.requestsSent, findings: scan.findings.length, reason: scan.stopReason || scan.error });
    running.delete(scanId);
    store.saveNow();
  }
  return scan;
}
