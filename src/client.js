import { redactHeaders, nowIso, sleep } from './util.js';
import { HARD_LIMITS, matchingHost, isLocalEntry, entryVerified, undertakingCurrent, authorizationConfirmed, targetConfig } from './scope.js';
import { safeFetch, hostRefusal } from './netguard.js';

/** Thrown when the scan must stop: user stop, budget, window, expiry or a stop condition. */
export class ScanHalt extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// DELETE is never sent, even with write methods authorized.
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const MAX_BODY = 256 * 1024;
const MAX_SYNTHETIC_BODY = 8 * 1024;
// Only sendSynthetic can set this, so a write cannot be sent without the endpoint's live opt-in.
const WRITE_APPROVED = Symbol('writeApproved');

export function globToRegex(glob) {
  const body = glob.trim().split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${body}$`, 'i');
}

export function applyAuth(headers, account, secretOverride) {
  const secret = secretOverride ?? account.secret;
  if (account.authType === 'bearer') headers.authorization = `Bearer ${secret}`;
  else if (account.authType === 'cookie') headers.cookie = secret;
  else headers[String(account.headerName || 'x-api-key').toLowerCase()] = secret;
}

const cap = (value, hard, fallback) => Math.min(Number.isFinite(Number(value)) ? Number(value) : fallback, hard);

/**
 * The only way checks can reach the network. Every request is checked against the recorded
 * authorization (undertaking, expiry, host, verification, method), the exclusions, the budgets,
 * the test window, and the stop/pause controls, and is paced to the configured rate. Hard
 * ceilings apply even if stored controls were edited to exceed them.
 */
export class GuardedClient {
  constructor({ project, scan, control, onLog, onResponse }) {
    this.project = project;
    this.authorization = project.authorization;
    this.controls = project.controls;
    this.base = new URL(project.target.baseUrl);
    this.scan = scan;
    this.control = control;
    this.onLog = onLog;
    this.onResponse = onResponse;
    this.exclusions = (this.controls.exclusions || []).filter((s) => s.trim()).map(globToRegex);
    this.maxRequests = cap(this.controls.maxRequests, HARD_LIMITS.maxRequests, 500);
    this.maxWrites = cap(this.controls.maxWrites, HARD_LIMITS.maxWrites, 25);
    this.maxDurationMs = cap(this.controls.maxDurationMs, HARD_LIMITS.maxDurationMs, 30 * 60_000);
    this.rps = Math.max(0.1, cap(this.controls.rps, HARD_LIMITS.rps, 5));
    this.burstRps = Math.max(0.1, cap(this.controls.burstRps, HARD_LIMITS.burstRps, 20));
    this.startedAt = Date.now();
    this.nextAt = 0;
    this.failStreak = 0;
    scan.writesSent ??= 0;
  }

  methodAllowed(method) {
    const m = method.toUpperCase();
    return SAFE_METHODS.has(m) || (WRITE_METHODS.has(m) && !!this.authorization.allowWriteMethods);
  }

  isExcluded(path) {
    return this.exclusions.some((r) => r.test(path));
  }

  halt(reason) {
    this.control.stopReason ??= reason;
    throw new ScanHalt(this.control.stopReason);
  }

  async gate() {
    while (this.control.paused && !this.control.stopReason) await sleep(200);
    if (this.control.stopReason) throw new ScanHalt(this.control.stopReason);
    const now = new Date();
    if (this.authorization.revokedAt) this.halt('Authorization was revoked.');
    if (new Date(this.authorization.expiresAt) <= now) this.halt('Authorization expired during the scan.');
    if (!undertakingCurrent(this.authorization)) this.halt('The testing undertaking is not accepted.');
    if (!authorizationConfirmed(this.authorization)) this.halt('The authorization is not confirmed by the authorizer.');
    if (this.controls.windowEnd && new Date(this.controls.windowEnd) <= now) this.halt('Test window closed.');
    if (this.scan.requestsSent >= this.maxRequests) this.halt(`Request budget of ${this.maxRequests} reached.`);
    if (Date.now() - this.startedAt > this.maxDurationMs) this.halt(`Maximum scan duration of ${Math.round(this.maxDurationMs / 60000)} minutes reached.`);
  }

  skip(reason, purpose) {
    this.onLog?.({ at: nowIso(), note: `Skipped (${purpose || 'request'}): ${reason}` });
    return { skipped: reason, status: 0, headers: {}, body: '', contentType: '' };
  }

  /** Sends `request` for endpoint `ep`: reads go straight through, writes need the per-endpoint opt-in. */
  sendFor(ep, request) {
    return SAFE_METHODS.has(ep.method.toUpperCase()) ? this.send(request) : this.sendSynthetic(ep, request);
  }

  /**
   * Any POST/PUT/PATCH. On top of the global write switch, the endpoint itself must be opted in by a person.
   * Mutated payloads (synthetic data) and the spec's own example bodies both go through here. The live record is looked up here, so a check cannot
   * pass a forged or stale endpoint, and a spec import can never grant it.
   */
  async sendSynthetic(endpoint, request) {
    const live = this.project.target.endpoints.find((e) => e.id === endpoint.id);
    const purpose = request.purpose || 'synthetic write';
    if (!live?.enabled || !live.syntheticWrites) return this.skip(`${endpoint.method} ${endpoint.path} is not opted in to synthetic writes`, purpose);
    if (!WRITE_METHODS.has(endpoint.method.toUpperCase())) return this.skip('synthetic payloads need POST, PUT or PATCH', purpose);
    const body = request.body;
    if (body !== undefined && Buffer.byteLength(typeof body === 'string' ? body : JSON.stringify(body)) > MAX_SYNTHETIC_BODY) {
      return this.skip('synthetic body is larger than 8 KB', purpose);
    }
    return this.send({ ...request, method: endpoint.method, endpoint: `${endpoint.method} ${endpoint.path}`, [WRITE_APPROVED]: true });
  }

  async send({ method = 'GET', path, query, headers = {}, body, account, authOverride, fromOrigin = false, burst = false, purpose = '', endpoint, [WRITE_APPROVED]: writeApproved = false }) {
    const m = method.toUpperCase();
    if (!this.methodAllowed(m)) return this.skip(`${m} is not permitted by the authorization`, purpose);
    const isWrite = !SAFE_METHODS.has(m);
    if (isWrite && !writeApproved) return this.skip(`${m} ${path} is not opted in to write requests`, purpose);
    if (isWrite && this.scan.writesSent >= this.maxWrites) return this.skip(`write budget of ${this.maxWrites} reached`, purpose);
    if (this.isExcluded(path)) return this.skip(`${path} is excluded`, purpose);

    const url = fromOrigin
      ? new URL(path, this.base.origin)
      : new URL(this.base.pathname.replace(/\/$/, '') + path, this.base.origin);
    for (const [k, v] of Object.entries(query || {})) url.searchParams.set(k, v);
    const entry = /^https?:$/.test(url.protocol) ? matchingHost(this.authorization, url.href) : undefined;
    if (!entry) return this.skip(`${url.host} is out of scope`, purpose);
    const network = targetConfig(this.project);
    const refusal = hostRefusal(entry, network);
    if (refusal) return this.skip(refusal, purpose);
    if (!isLocalEntry(entry, this.project) && !entryVerified(this.project, entry)) return this.skip(`control of ${entry} is not verified`, purpose);

    const rps = burst ? this.burstRps : this.rps;
    const wait = this.nextAt - Date.now();
    if (wait > 0) await sleep(wait);
    await this.gate();
    this.nextAt = Date.now() + 1000 / rps;

    const h = {
      'user-agent': `breakAPI/0.1 (authorized assessment; scan ${this.scan.id})`,
      'x-breakapi-scan': this.scan.id,
      ...headers,
    };
    if (account) applyAuth(h, account, authOverride);
    let payload;
    if (body !== undefined && m !== 'GET' && m !== 'HEAD') {
      payload = typeof body === 'string' ? body : JSON.stringify(body);
      h['content-type'] ??= 'application/json';
    }

    this.scan.requestsSent++;
    if (isWrite) this.scan.writesSent++;
    const started = Date.now();
    let res;
    try {
      // Guarded DNS: the resolved address is checked at connect time, so it cannot be rebound to a forbidden one.
      res = await safeFetch(url, { method: m, headers: h, body: payload, timeoutMs: this.controls.timeoutMs, maxBody: MAX_BODY, config: network });
    } catch (err) {
      res = { status: 0, headers: {}, setCookies: [], body: '', error: err.code === 'TIMEOUT' ? 'timeout' : err.code === 'EBREAKAPI_BLOCKED' ? err.message : err.code || err.message };
    }
    Object.assign(res, {
      ms: Date.now() - started,
      method: m,
      url: url.href,
      endpoint: endpoint || `${m} ${path}`,
      contentType: res.headers['content-type'] || '',
      requestHeaders: redactHeaders(h, account?.authType === 'header' ? [account.headerName] : []),
      requestBody: isWrite ? payload : undefined,
    });

    const who = account ? `${account.label}${authOverride ? ' (modified credential)' : ''}` : 'anonymous';
    this.onLog?.({ at: nowIso(), method: m, url: url.pathname + url.search, status: res.status, ms: res.ms, purpose, account: who, error: res.error });
    this.onResponse?.(res);

    if (res.status === 0 || res.status >= 500) {
      this.failStreak++;
      if (this.failStreak >= this.controls.stopOnErrorStreak) {
        this.halt(`Stop condition: ${this.failStreak} consecutive server errors or timeouts.`);
      }
    } else {
      this.failStreak = 0;
    }
    return res;
  }
}
