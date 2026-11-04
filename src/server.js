import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Store } from './store.js';
import { loadKey, encrypt, decrypt } from './crypto.js';
import { importSpec } from './importers.js';
import { ALL_TESTS, TEST_LABELS, HARD_LIMITS, preflight, needsVerification, hostStatus, isLocalEntry, matchingHost } from './scope.js';
import { UNDERTAKING_VERSION, UNDERTAKING_CLAUSES, LEGAL_NOTICE, AUTH_LIMITATIONS, hashUndertaking, typedNameMatches } from './undertaking.js';
import { challengeHost } from './verify.js';
import { createScan, runScan, running, audit } from './scanner.js';
import { renderReport, LIMITATIONS } from './report.js';
import { createLab } from './lab.js';
import { createSimClient, SimError } from './simclient.js';
import { startEmbeddedSim, SIM_PREFIX } from './simembed.js';
import { newId, nowIso, mask, clamp } from './util.js';
import { setConfig, publicConfig } from './config.js';
import { createMailer } from './mail.js';
import { hashPassword, verifyPassword, burnTime, passwordProblem, normalizeEmail, validEmail, randomToken, sha256, RateLimiter, publicUser } from './auth.js';

export const VERSION = '0.2.0';
const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/report.css': ['report.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
  '/EXAMPLES.md': ['../EXAMPLES.md', 'text/plain; charset=utf-8'],
  '/fonts/jetbrains-mono.woff2': ['fonts/jetbrains-mono.woff2', 'font/woff2'],
  '/fonts/jetbrains-mono-italic.woff2': ['fonts/jetbrains-mono-italic.woff2', 'font/woff2'],
};
const STATIC_CACHE = { '/fonts/jetbrains-mono.woff2': true, '/fonts/jetbrains-mono-italic.woff2': true, '/favicon.svg': true };
const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'cross-origin-opener-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cache-control': 'no-store',
};
const MAX_AUTH_DAYS = 90;
const SESSION_COOKIE = 'bp_sid';
const ABSOLUTE_SESSION_MS = 7 * 86400_000;
// Accounts an admin issues work for 30 days at most, and only while this run of the app lasts.
const ACCESS_MS = 30 * 86400_000;
const TOKEN_TTL = { verify: 48 * 3600_000, reset: 3600_000, authconfirm: 72 * 3600_000 };

export const DEFAULT_CONTROLS = {
  maxRequests: 500,
  rps: 5,
  burstRps: 20,
  rateLimitBurst: 30,
  timeoutMs: 10000,
  stopOnErrorStreak: 10,
  exclusions: [],
  windowStart: null,
  windowEnd: null,
  monitoringContact: '',
  maxWrites: 50,
  maxDurationMs: 30 * 60_000,
};

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}
const bad = (msg) => new HttpError(400, msg);
const notFound = (what = 'Not found') => new HttpError(404, what);

// JSON bodies never get to set prototypes (__proto__ / constructor / prototype keys are dropped).
const reviver = (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype' ? undefined : v);

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'), reviver);
        resolve(v && typeof v === 'object' ? v : {});
      } catch {
        reject(bad('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

const isoOrNull = (v, field) => {
  if (v === null || v === undefined || v === '') return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw bad(`${field} is not a valid date`);
  return d.toISOString();
};

function scanSummary(s) {
  const counts = {};
  for (const f of s.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return { id: s.id, status: s.status, createdAt: s.createdAt, startedAt: s.startedAt, finishedAt: s.finishedAt, requestsSent: s.requestsSent, counts, previousScanId: s.previousScanId, stopReason: s.stopReason, startedBy: s.startedBy?.email };
}

function purgeCredentials(project, reason) {
  let n = 0;
  for (const a of project.accounts || []) {
    if (a.secretEnc) {
      delete a.secretEnc;
      a.purgedAt = nowIso();
      n++;
    }
  }
  if (n) audit(project, 'credentials.purged', { count: n, reason });
  return n;
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i)] = decodeURIComponent(part.slice(i + 1));
  }
  return out;
}

export function createApp({ config, log = console } = {}) {
  if (!config) throw new Error('createApp needs a config (see src/config.js loadConfig)');
  setConfig(config);
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const store = new Store(config.dataDir);
  const data = store.data;
  data.users ??= {};
  data.sessions ??= {};
  data.tokens ??= {};
  data.systemAudit ??= [];
  const key = config.secretKey ? Buffer.from(config.secretKey, 'base64') : loadKey(config.dataDir);
  const mailer = createMailer(config, { log });
  const limiter = new RateLimiter();
  // The simulation is either a separate server (BREAKAPI_SIM_URL) or a checkout run inside this process
  // (BREAKAPI_SIM_EMBED_DIR). Embedded, it starts asynchronously: `ready` settles once it is up, and the
  // lab's calls wait for it. A failed start is logged and turns the playground off; nothing else is affected.
  let embedded = null;
  let sim = null;
  let simBase = config.simUrl;
  let ready = Promise.resolve(false);
  if (config.simEmbedDir) {
    simBase = `${config.simPublicUrl}${SIM_PREFIX}`;
    const started = startEmbeddedSim({ dir: config.simEmbedDir, publicBase: simBase, log })
      .then((e) => {
        embedded = e;
        return createSimClient({ url: e.url, key: e.key });
      });
    started.catch((err) => log.error?.(`The embedded simulation did not start: ${err.message}`));
    ready = started.then(() => true, () => false);
    const through = (name) => async (...args) => {
      const client = await started.catch(() => { throw new SimError(503, 'The simulation is not available.'); });
      return client[name](...args);
    };
    sim = {
      host: new URL(config.simPublicUrl).host,
      catalog: through('catalog'), create: through('create'), get: through('get'),
      configure: through('configure'), reset: through('reset'), remove: through('remove'), spec: through('spec'),
    };
  } else if (config.simUrl && config.simControlKey) {
    sim = createSimClient({ url: config.simUrl, key: config.simControlKey });
  }
  const lab = createLab({ key, log, sim, simUrl: simBase, dailyRuns: config.labDailyRuns });
  const appRun = randomToken(9);
  let server;

  const sysAudit = (event, detail = {}) => {
    data.systemAudit.push({ at: nowIso(), event, ...detail });
    if (data.systemAudit.length > 5000) data.systemAudit.splice(0, data.systemAudit.length - 5000);
  };

  // ----- migrations from the single-operator version -----
  for (const s of Object.values(data.scans)) {
    if (['running', 'queued', 'paused'].includes(s.status)) {
      s.status = 'interrupted';
      s.stopReason = 'The breakAPI server restarted during the scan.';
    }
  }
  for (const p of Object.values(data.projects)) {
    p.members ??= p.ownerId ? [{ userId: p.ownerId, role: 'owner', addedAt: p.createdAt }] : [];
    const a = p.authorization;
    if (a && a.undertaking && !a.confirmedAt) {
      a.confirmedAt = a.undertaking.acceptedAt;
      a.confirmedVia = 'recorded before email confirmation existed';
    }
  }
  const legacyToken = join(config.dataDir, 'access-token');
  if (existsSync(legacyToken)) unlinkSync(legacyToken);

  // First-run: with no users yet, an operator creates the first admin with a one-time setup token.
  const setupFile = join(config.dataDir, 'setup-token');
  const hasUsers = () => Object.keys(data.users).length > 0;
  let setupToken = null;
  if (!hasUsers()) {
    if (!existsSync(setupFile)) writeFileSync(setupFile, randomToken(18), { mode: 0o600 });
    setupToken = readFileSync(setupFile, 'utf8').trim();
  } else if (existsSync(setupFile)) unlinkSync(setupFile);

  const linkBase = () => config.publicUrl || `http://${['0.0.0.0', '::', '127.0.0.1'].includes(config.host) ? 'localhost' : config.host}:${server?.address()?.port || config.port}`;

  // ----- tokens (single use, stored hashed) -----
  const issueToken = (type, fields) => {
    const raw = randomToken();
    data.tokens[sha256(raw)] = { type, ...fields, createdAt: nowIso(), expiresAt: new Date(Date.now() + TOKEN_TTL[type]).toISOString() };
    return raw;
  };
  const peekToken = (type, raw) => {
    const t = data.tokens[sha256(String(raw || ''))];
    if (!t || t.type !== type || t.usedAt || new Date(t.expiresAt) <= new Date()) return null;
    return t;
  };
  const consumeToken = (type, raw) => {
    const t = peekToken(type, raw);
    if (!t) throw new HttpError(410, 'This link is invalid, already used or expired. Request a new one.');
    t.usedAt = nowIso();
    return t;
  };
  const revokeTokens = (pred) => {
    for (const t of Object.values(data.tokens)) if (!t.usedAt && pred(t)) t.usedAt = nowIso();
  };

  // ----- access for accounts an admin issued -----
  /** Why this account can't be used right now, or null if it can. Administrators have no time limit. */
  const accessEnded = (u) => {
    if (u.role === 'admin') return null;
    if (!u.access) return 'This account has no active access. Ask your administrator to issue it again.';
    if (u.access.runId !== appRun) return 'Your access ended when the app restarted. Ask your administrator to issue it again.';
    if (new Date(u.access.expiresAt) <= new Date()) return 'Your 30 days of access have ended. Ask your administrator to issue it again.';
    return null;
  };
  /** Sets a new setup token and 30-day limit. Returns what the admin hands over; only hashes are kept. */
  const issueAccess = (u, password, by) => {
    const setupToken = randomToken(18);
    const pass = password || randomToken(15);
    checkNewPassword(pass, u.email);
    const expiresAt = new Date(Date.now() + ACCESS_MS).toISOString();
    u.passwordHash = hashPassword(pass);
    u.emailVerifiedAt ??= nowIso();
    u.access = { tokenHash: sha256(setupToken), issuedAt: nowIso(), issuedBy: by, expiresAt, runId: appRun };
    endSessions((s) => s.userId === u.id);
    return { email: u.email, password: pass, setupToken, expiresAt };
  };

  // ----- sessions (random id in an HttpOnly cookie; only its hash is stored) -----
  const secureCookies = (req) => config.publicUrl.startsWith('https://') || (config.trustProxy && req.headers['x-forwarded-proto'] === 'https');
  const cookie = (req, value, maxAgeSec) => `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secureCookies(req) ? '; Secure' : ''}`;
  const clientIp = (req) => (config.trustProxy && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';

  const accessLimited = (u) => u.role !== 'admin' && !!u.access;
  const startSession = (req, res, user) => {
    const raw = randomToken();
    const now = Date.now();
    // An issued account has one session at a time, lasting as long as its access does.
    const limited = accessLimited(user);
    if (limited) endSessions((s) => s.userId === user.id);
    data.sessions[sha256(raw)] = { userId: user.id, ...(limited ? { expiresAt: user.access.expiresAt } : {}), createdAt: new Date(now).toISOString(), lastSeenAt: new Date(now).toISOString(), ip: clientIp(req), userAgent: String(req.headers['user-agent'] || '').slice(0, 200) };
    res.setHeader('set-cookie', cookie(req, raw, limited ? Math.floor((new Date(user.access.expiresAt) - now) / 1000) : config.sessionHours * 3600));
    user.lastLoginAt = nowIso();
    store.save();
  };
  const endSessions = (pred) => {
    for (const [h, s] of Object.entries(data.sessions)) if (pred(s, h)) delete data.sessions[h];
  };
  const sessionFor = (req) => {
    const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!raw) return null;
    const h = sha256(raw);
    const s = data.sessions[h];
    if (!s) return null;
    const now = Date.now();
    const user = data.users[s.userId];
    const idle = !s.expiresAt && now - new Date(s.lastSeenAt) > config.sessionHours * 3600_000;
    const old = !s.expiresAt && now - new Date(s.createdAt) > ABSOLUTE_SESSION_MS;
    if (!user || user.disabledAt || idle || old || accessEnded(user)) {
      delete data.sessions[h];
      store.save();
      return null;
    }
    if (now - new Date(s.lastSeenAt) > 60_000) {
      s.lastSeenAt = new Date(now).toISOString();
      store.save();
    }
    return { hash: h, session: s, user };
  };

  const sendMail = async (to, subject, text) => {
    try {
      await mailer.send({ to, subject, text });
    } catch (err) {
      log.error?.(`[mail] failed to send "${subject}" to ${to}: ${err.message}`);
      throw new HttpError(502, 'The email could not be sent. Check the mail settings and try again.');
    }
  };
  const sendVerification = (user) => {
    revokeTokens((t) => t.type === 'verify' && t.userId === user.id);
    const raw = issueToken('verify', { userId: user.id, email: user.email });
    return sendMail(user.email, 'Verify your email for breakAPI', `Hi ${user.name || ''},\n\nConfirm that this address belongs to you, so you can run security tests with breakAPI:\n\n${linkBase()}/#/verify/${raw}\n\nThe link works once and expires in 48 hours. If you didn't sign up, ignore this email.\n`);
  };

  const rate = (req, name, limit, windowMs, extraKey = '') => {
    const r = limiter.hit(`${name}:${clientIp(req)}:${extraKey}`, limit, windowMs);
    if (!r.ok) throw new HttpError(429, `Too many attempts. Try again in ${Math.ceil(r.retryAfter / 60)} minute(s).`, { retryAfter: r.retryAfter });
  };

  // ----- projects & membership -----
  const memberRole = (p, user) => p.members?.find((m) => m.userId === user.id)?.role || null;
  const getProject = (id, user) => {
    const p = data.projects[id];
    // Non-members get the same 404 as a missing project, so ids can't be probed.
    if (!p || !memberRole(p, user)) throw notFound('Project not found');
    return p;
  };
  const ownerOnly = (p, user) => {
    if (memberRole(p, user) !== 'owner') throw new HttpError(403, 'Only the project owner can do this.');
  };
  const getScan = (id, user) => {
    const s = data.scans[id];
    if (!s) throw notFound('Scan not found');
    getProject(s.projectId, user);
    return s;
  };
  const runningScansFor = (projectId) => [...running.keys()].filter((id) => data.scans[id]?.projectId === projectId);
  /** Stops the project's scans, then removes it with its scans, reports and pending links. */
  const removeProject = (p, byEmail) => {
    for (const [id, s] of Object.entries(data.scans)) {
      if (s.projectId !== p.id) continue;
      const ctl = running.get(id);
      if (ctl) Object.assign(ctl, { stopReason: 'Project deleted.', userStopped: true });
      delete data.scans[id];
    }
    revokeTokens((t) => t.projectId === p.id);
    delete data.projects[p.id];
    sysAudit('project.deleted', { name: p.name, by: byEmail });
    store.saveNow();
  };
  const orphans = () => Object.values(data.projects).filter((p) => !p.members?.length);
  const sanitizeProject = (p, user) => ({
    ...p,
    accounts: (p.accounts || []).map(({ secretEnc, ...rest }) => ({ ...rest, hasSecret: !!secretEnc })),
    problems: preflight(p),
    hostStatus: p.authorization ? hostStatus(p) : [],
    needsVerification: p.target?.baseUrl ? needsVerification(p.target.baseUrl) : false,
    running: runningScansFor(p.id),
    myRole: memberRole(p, user),
    members: (p.members || []).map((m) => ({ userId: m.userId, role: m.role, email: data.users[m.userId]?.email, name: data.users[m.userId]?.name })),
  });

  const verifyEntry = async (p, entry) => {
    const a = p.authorization;
    let scheme = 'https';
    try {
      const base = new URL(p.target.baseUrl);
      if (matchingHost(a, base.href) === entry) scheme = base.protocol.replace(':', '');
    } catch { /* no base URL yet: default to https */ }
    const result = await challengeHost({ entry, scheme, token: a.verificationToken });
    p.verifiedHosts = (p.verifiedHosts || []).filter((v) => !(v.host === entry && v.authorizationId === a.id));
    if (result.ok) {
      p.verifiedHosts.push({ host: entry, method: result.method, at: nowIso(), authorizationId: a.id });
      audit(p, 'host.verified', { host: entry, method: result.method });
    } else {
      audit(p, 'host.verification_failed', { host: entry, reason: result.error });
    }
    store.saveNow();
    return result;
  };

  const startScan = async (project, user, previousScanId) => {
    if (runningScansFor(project.id).length) throw new HttpError(409, 'A scan is already running for this project.');
    // Lab runs have their own cap, so anonymous demo visitors can't use up the slots for real scans.
    const busy = [...running.keys()].filter((id) => data.scans[id]).length;
    if (busy >= config.maxConcurrentScans) throw new HttpError(429, `The server is already running ${busy} scans. Try again when one finishes.`);
    const problems = preflight(project);
    if (problems.length) throw new HttpError(422, `Scan blocked: ${problems.join(' ')}`);
    for (const entry of project.authorization.allowedHosts.filter((h) => !isLocalEntry(h, project))) {
      const r = await verifyEntry(project, entry);
      if (!r.ok) throw new HttpError(422, `Scan blocked: re-verification of "${entry}" failed. ${r.error}`);
    }
    const scan = createScan(store, project, { previousScanId });
    scan.startedBy = { userId: user.id, email: user.email, name: user.name, emailVerifiedAt: user.emailVerifiedAt };
    scan.verificationSnapshot = hostStatus(project);
    audit(project, 'scan.requested', { scanId: scan.id, by: user.email });
    store.saveNow();
    runScan({ store, key }, scan.id).catch((err) => log.error?.('scan crashed', err));
    return scan;
  };

  // ----- retention sweep -----
  const sweep = () => {
    let changed = false;
    for (const p of Object.values(data.projects)) {
      const a = p.authorization;
      if (a && (a.revokedAt || new Date(a.expiresAt) <= new Date())) {
        if (purgeCredentials(p, a.revokedAt ? 'authorization revoked' : 'authorization expired')) changed = true;
      }
    }
    const now = Date.now();
    for (const [h, t] of Object.entries(data.tokens)) {
      if (now - new Date(t.expiresAt) > 7 * 86400_000) { delete data.tokens[h]; changed = true; }
    }
    for (const [h, s] of Object.entries(data.sessions)) {
      if (s.expiresAt ? now > new Date(s.expiresAt) : now - new Date(s.createdAt) > ABSOLUTE_SESSION_MS) { delete data.sessions[h]; changed = true; }
    }
    // Scans stop when the access of whoever started them ends.
    for (const id of running.keys()) {
      const starter = data.users[data.scans[id]?.startedBy?.userId];
      if (starter && accessEnded(starter)) Object.assign(running.get(id), { stopReason: 'The access of the user who started this scan has ended.', userStopped: true });
    }
    if (changed) store.saveNow();
  };
  sweep();
  const sweeper = setInterval(sweep, 60_000);
  sweeper.unref();

  const userCount = () => Object.values(data.users).length;
  const findUserByEmail = (email) => Object.values(data.users).find((u) => u.email === normalizeEmail(email));
  const adminsLeft = (exceptId) => Object.values(data.users).filter((u) => u.role === 'admin' && !u.disabledAt && u.id !== exceptId).length;
  const newUser = ({ email, name, role, password, verified }) => {
    const u = {
      id: newId('usr'),
      email: normalizeEmail(email),
      name: String(name || '').trim().slice(0, 120),
      role: role === 'admin' ? 'admin' : 'user',
      passwordHash: password ? hashPassword(password) : null,
      emailVerifiedAt: verified ? nowIso() : null,
      createdAt: nowIso(),
    };
    data.users[u.id] = u;
    return u;
  };
  const checkNewPassword = (password, email) => {
    const why = passwordProblem(password, email);
    if (why) throw bad(why);
  };

  const labEnabled = () => {
    if (!config.lab) throw notFound('The demo lab is turned off on this server.');
  };

  // ----- routes -----
  // opts: public (no session), admin, verified (email verified), limit (body bytes)
  const routes = [
    // --- health ---
    // /healthz and /readyz suit Docker and Kubernetes. Google-hosted platforms (Cloud Run, which Replit
    // deployments use) answer /healthz themselves and never forward it, so /api/healthz is the one to use there.
    ['GET', /^\/(?:api\/)?healthz$/, async () => ({ ok: true, version: VERSION }), { public: true, raw: true }],
    ['GET', /^\/(?:api\/)?readyz$/, async () => {
      store.saveNow();
      return { ok: true, users: userCount(), runningScans: running.size };
    }, { public: true, raw: true }],

    // --- auth ---
    ['GET', /^\/api\/auth\/me$/, async ({ req }) => {
      const s = sessionFor(req);
      return { user: publicUser(s?.user), setupRequired: !hasUsers(), lab: config.lab, mailMode: mailer.mode, env: config.env, version: VERSION };
    }, { public: true }],
    ['POST', /^\/api\/auth\/setup$/, async ({ req, res, body }) => {
      rate(req, 'setup', 10, 15 * 60_000);
      if (hasUsers()) throw new HttpError(409, 'Setup is already complete. Sign in instead.');
      if (!setupToken || String(body.setupToken || '').trim() !== setupToken) throw new HttpError(403, 'That setup token is not correct. It is printed in the server log and saved in the data directory as setup-token.');
      const email = normalizeEmail(body.email);
      if (!validEmail(email)) throw bad('Enter a valid email address.');
      if (!String(body.name || '').trim()) throw bad('Enter your name.');
      checkNewPassword(body.password, email);
      // The setup token proves control of the server, so the first admin's email counts as verified.
      const u = newUser({ email, name: body.name, role: 'admin', password: body.password, verified: true });
      for (const p of Object.values(data.projects)) {
        if (!p.members.length) p.members.push({ userId: u.id, role: 'owner', addedAt: nowIso() });
      }
      setupToken = null;
      if (existsSync(setupFile)) unlinkSync(setupFile);
      sysAudit('setup.completed', { by: u.email });
      startSession(req, res, u);
      store.saveNow();
      return { user: publicUser(u) };
    }, { public: true, limit: 16_384 }],
    ['POST', /^\/api\/auth\/login$/, async ({ req, res, body }) => {
      const email = normalizeEmail(body.email);
      rate(req, 'login-ip', 30, 15 * 60_000);
      rate(req, 'login-account', 8, 15 * 60_000, email);
      const u = findUserByEmail(email);
      const generic = new HttpError(401, 'Those details aren\'t right, or the account is not active. Invited users also need their setup token.');
      if (!u || !u.passwordHash) {
        burnTime(body.password);
        throw generic;
      }
      if (!verifyPassword(body.password, u.passwordHash) || u.disabledAt) {
        sysAudit('user.login_failed', { userId: u.id, ip: clientIp(req) });
        store.save();
        throw generic;
      }
      // An issued account needs its setup token on every sign-in, as well as the password.
      if (accessLimited(u) && sha256(String(body.setupToken || '').trim()) !== u.access.tokenHash) {
        sysAudit('user.login_failed', { userId: u.id, ip: clientIp(req) });
        store.save();
        throw generic;
      }
      const ended = accessEnded(u);
      if (ended) throw new HttpError(403, ended);
      limiter.reset(`login-account:${clientIp(req)}:${email}`);
      // Rotate: a fresh session id on every login (no session fixation).
      const prior = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      if (prior) delete data.sessions[sha256(prior)];
      startSession(req, res, u);
      sysAudit('user.login', { userId: u.id, ip: clientIp(req) });
      return { user: publicUser(u) };
    }, { public: true, limit: 16_384 }],
    ['POST', /^\/api\/auth\/logout$/, async ({ req, res }) => {
      const s = sessionFor(req);
      if (s) delete data.sessions[s.hash];
      res.setHeader('set-cookie', cookie(req, '', 0));
      store.save();
      return { ok: true };
    }, { public: true }],
    ['POST', /^\/api\/auth\/logout-all$/, async ({ req, res, user }) => {
      endSessions((s) => s.userId === user.id);
      res.setHeader('set-cookie', cookie(req, '', 0));
      sysAudit('user.logout_all', { userId: user.id });
      store.saveNow();
      return { ok: true };
    }],
    ['POST', /^\/api\/auth\/verify$/, async ({ body }) => {
      const t = consumeToken('verify', body.token);
      const u = data.users[t.userId];
      if (!u || u.email !== t.email) throw new HttpError(410, 'This link no longer matches an account.');
      u.emailVerifiedAt = nowIso();
      sysAudit('user.email_verified', { userId: u.id });
      store.saveNow();
      return { ok: true, email: u.email };
    }, { public: true }],
    ['POST', /^\/api\/auth\/resend-verification$/, async ({ req, user }) => {
      rate(req, 'resend', 3, 3600_000, user.id);
      if (user.emailVerifiedAt) return { ok: true, alreadyVerified: true };
      await sendVerification(user);
      store.saveNow();
      return { ok: true };
    }],
    ['POST', /^\/api\/auth\/forgot$/, async ({ req, body }) => {
      const email = normalizeEmail(body.email);
      rate(req, 'forgot', 5, 3600_000);
      rate(req, 'forgot-account', 3, 3600_000, email);
      const u = findUserByEmail(email);
      if (u && !u.disabledAt) {
        revokeTokens((t) => t.type === 'reset' && t.userId === u.id);
        const raw = issueToken('reset', { userId: u.id, email: u.email });
        await sendMail(u.email, 'Reset your breakAPI password', `A password reset was requested for this address.\n\nChoose a new password here (the link works once and expires in 1 hour):\n\n${linkBase()}/#/reset/${raw}\n\nIf you didn't ask for this, ignore this email; your password stays the same.\n`);
        sysAudit('user.reset_requested', { userId: u.id });
        store.saveNow();
      }
      return { ok: true, message: 'If an account exists for that address, a reset link is on its way.' };
    }, { public: true, limit: 16_384 }],
    ['POST', /^\/api\/auth\/reset$/, async ({ body }) => {
      const t = peekToken('reset', body.token);
      if (!t) throw new HttpError(410, 'This link is invalid, already used or expired. Request a new one.');
      const u = data.users[t.userId];
      if (!u || u.disabledAt) throw new HttpError(410, 'This link no longer matches an active account.');
      checkNewPassword(body.password, u.email);
      consumeToken('reset', body.token);
      u.passwordHash = hashPassword(body.password);
      u.emailVerifiedAt ??= nowIso(); // they proved they read this inbox
      endSessions((s) => s.userId === u.id);
      sysAudit('user.password_reset', { userId: u.id });
      store.saveNow();
      return { ok: true };
    }, { public: true, limit: 16_384 }],
    ['POST', /^\/api\/auth\/password$/, async ({ req, body, user, session }) => {
      rate(req, 'password', 10, 3600_000, user.id);
      if (!verifyPassword(body.current, user.passwordHash)) throw bad('Your current password is not correct.');
      checkNewPassword(body.password, user.email);
      user.passwordHash = hashPassword(body.password);
      endSessions((s, h) => s.userId === user.id && h !== session.hash); // other devices are signed out
      sysAudit('user.password_changed', { userId: user.id });
      store.saveNow();
      return { ok: true };
    }, { limit: 16_384 }],
    ['PATCH', /^\/api\/auth\/profile$/, async ({ body, user }) => {
      const name = String(body.name || '').trim();
      if (!name) throw bad('Enter your name.');
      user.name = name.slice(0, 120);
      store.saveNow();
      return { user: publicUser(user) };
    }],
    ['GET', /^\/api\/auth\/sessions$/, async ({ user, session }) => Object.entries(data.sessions)
      .filter(([, s]) => s.userId === user.id)
      .map(([h, s]) => ({ current: h === session.hash, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, ip: s.ip, userAgent: s.userAgent }))],

    // --- admin ---
    ['GET', /^\/api\/admin\/overview$/, async () => ({
      version: VERSION,
      config: publicConfig(config),
      counts: { orphans: orphans().length, users: userCount(), admins: Object.values(data.users).filter((u) => u.role === 'admin').length, projects: Object.keys(data.projects).length, scans: Object.keys(data.scans).length, runningScans: running.size, sessions: Object.keys(data.sessions).length },
    }), { admin: true }],
    ['GET', /^\/api\/admin\/users$/, async () => Object.values(data.users)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .map((u) => ({ ...publicUser(u), accessEnded: accessEnded(u), projects: Object.values(data.projects).filter((p) => memberRole(p, u)).length })), { admin: true }],
    ['POST', /^\/api\/admin\/users$/, async ({ body, user }) => {
      const email = normalizeEmail(body.email);
      if (!validEmail(email)) throw bad('Enter a valid email address.');
      if (findUserByEmail(email)) throw new HttpError(409, 'A user with that email already exists.');
      if (body.password) checkNewPassword(body.password, email);
      const u = newUser({ email, name: body.name, role: 'user', verified: true });
      const credentials = issueAccess(u, body.password, user.email);
      sysAudit('user.issued', { userId: u.id, by: user.email });
      store.saveNow();
      return { user: publicUser(u), credentials };
    }, { admin: true, limit: 16_384 }],
    ['PATCH', /^\/api\/admin\/users\/(\w+)$/, async ({ m, body, user }) => {
      const u = data.users[m[1]];
      if (!u) throw notFound('User not found');
      if ('role' in body) {
        const role = body.role === 'admin' ? 'admin' : 'user';
        if (u.role === 'admin' && role !== 'admin' && !adminsLeft(u.id)) throw bad('There must be at least one active administrator.');
        if (u.role !== role) {
          sysAudit('user.role_changed', { userId: u.id, role, by: user.email });
          // Sign-in rules differ by role, so start again: an admin has no time limit, and a former admin needs issuing.
          delete u.access;
          endSessions((s) => s.userId === u.id);
        }
        u.role = role;
      }
      if ('disabled' in body) {
        if (body.disabled && u.id === user.id) throw bad('You cannot disable your own account.');
        if (body.disabled && u.role === 'admin' && !adminsLeft(u.id)) throw bad('There must be at least one active administrator.');
        u.disabledAt = body.disabled ? (u.disabledAt || nowIso()) : null;
        if (body.disabled) {
          endSessions((s) => s.userId === u.id);
          for (const p of Object.values(data.projects)) {
            for (const id of runningScansFor(p.id)) {
              if (data.scans[id]?.startedBy?.userId === u.id) Object.assign(running.get(id), { stopReason: 'The user who started this scan was disabled.', userStopped: true });
            }
          }
        }
        sysAudit(body.disabled ? 'user.disabled' : 'user.enabled', { userId: u.id, by: user.email });
      }
      store.saveNow();
      return publicUser(u);
    }, { admin: true }],
    ['POST', /^\/api\/admin\/users\/(\w+)\/reissue$/, async ({ m, body, user }) => {
      const u = data.users[m[1]];
      if (!u) throw notFound('User not found');
      if (u.role === 'admin') throw bad('Administrators sign in without a setup token, so there is nothing to issue.');
      const credentials = issueAccess(u, body.password, user.email);
      sysAudit('user.reissued', { userId: u.id, by: user.email });
      store.saveNow();
      return { user: publicUser(u), credentials };
    }, { admin: true, limit: 16_384 }],
    ['DELETE', /^\/api\/admin\/users\/(\w+)$/, async ({ m, user }) => {
      const u = data.users[m[1]];
      if (!u) throw notFound('User not found');
      if (u.id === user.id) throw bad('You cannot delete your own account.');
      if (u.role === 'admin' && !adminsLeft(u.id)) throw bad('There must be at least one active administrator.');
      const owned = Object.values(data.projects).filter((p) => memberRole(p, u) === 'owner');
      if (owned.length) throw bad(`This user owns ${owned.length} project(s). Transfer or delete them first, or disable the account instead.`);
      for (const p of Object.values(data.projects)) p.members = p.members.filter((x) => x.userId !== u.id);
      endSessions((s) => s.userId === u.id);
      revokeTokens((t) => t.userId === u.id);
      delete data.users[u.id];
      sysAudit('user.deleted', { email: u.email, by: user.email });
      store.saveNow();
      return { ok: true };
    }, { admin: true }],
    // Projects nobody can open: they predate accounts (carried over from the single-operator version) and
    // were never assigned. Admins see only name, address and scan count, and can claim or delete them.
    ['GET', /^\/api\/admin\/orphans$/, async () => orphans().map((p) => ({ id: p.id, name: p.name, createdAt: p.createdAt, baseUrl: p.target?.baseUrl || '', scans: Object.values(data.scans).filter((s) => s.projectId === p.id).length })), { admin: true }],
    ['POST', /^\/api\/admin\/orphans\/(\w+)\/claim$/, async ({ m, user }) => {
      const p = orphans().find((x) => x.id === m[1]);
      if (!p) throw notFound('No unowned project with that id');
      p.members = [{ userId: user.id, role: 'owner', addedAt: nowIso() }];
      audit(p, 'project.claimed', { by: user.email });
      sysAudit('project.claimed', { name: p.name, by: user.email });
      store.saveNow();
      return { ok: true, id: p.id };
    }, { admin: true }],
    ['DELETE', /^\/api\/admin\/orphans\/(\w+)$/, async ({ m, user }) => {
      const p = orphans().find((x) => x.id === m[1]);
      if (!p) throw notFound('No unowned project with that id');
      removeProject(p, user.email);
      return { ok: true };
    }, { admin: true }],
    ['GET', /^\/api\/admin\/audit$/, async () => data.systemAudit.slice(-500).reverse().map((e) => ({ ...e, email: e.userId ? data.users[e.userId]?.email : undefined })), { admin: true }],

    // --- demo lab: public. Only an example id, or a preset / catalog ids for the playground, is ever read
    // from a request: never a host, URL, header or credential. ---
    ['GET', /^\/api\/lab$/, async () => {
      labEnabled();
      return { examples: lab.examples(), playground: await lab.playground() };
    }, { public: true }],
    ['POST', /^\/api\/lab\/runs$/, async ({ req, body }) => {
      labEnabled();
      rate(req, 'lab', 20, 15 * 60_000);
      const wantsPlayground = body.preset !== undefined || body.vulns !== undefined;
      const r = wantsPlayground
        ? await lab.startPlayground({ preset: typeof body.preset === 'string' ? body.preset : undefined, vulns: body.vulns })
        : lab.start(String(body.exampleId || ''));
      if (r.error) throw new HttpError(r.error, r.message);
      return r;
    }, { public: true, limit: 4096 }],
    ['POST', /^\/api\/lab\/runs\/([\w-]+)\/retest$/, async ({ req, m, body }) => {
      labEnabled();
      rate(req, 'lab', 20, 15 * 60_000);
      const r = await lab.retest(m[1], { preset: typeof body.preset === 'string' ? body.preset : undefined, vulns: body.vulns });
      if (r.error) throw new HttpError(r.error, r.message);
      return r;
    }, { public: true, limit: 4096 }],
    ['GET', /^\/api\/lab\/runs\/([\w-]+)$/, async ({ m }) => {
      labEnabled();
      const r = lab.view(m[1]);
      if (!r) throw notFound('This run is no longer available. Runs are kept for an hour.');
      return r;
    }, { public: true }],
    ['POST', /^\/api\/lab\/runs\/([\w-]+)\/stop$/, async ({ m }) => {
      labEnabled();
      if (!lab.stop(m[1])) throw notFound('This run is no longer available.');
      return { ok: true };
    }, { public: true, limit: 1024 }],

    // --- authorization confirmation by the authorizer (link from email; no account needed) ---
    ['GET', /^\/api\/confirm\/([\w-]+)$/, async ({ m }) => {
      const t = peekToken('authconfirm', m[1]);
      const p = t && data.projects[t.projectId];
      const a = p?.authorization;
      if (!a || a.id !== t.authorizationId || a.revokedAt || a.confirmedAt) throw new HttpError(410, 'This confirmation link is invalid, already used, expired or replaced by a newer authorization.');
      return {
        projectName: p.name,
        recordedBy: a.recordedBy,
        authorizerName: a.authorizerName,
        authorizerEmail: a.authorizerEmail,
        authorizerRole: a.authorizerRole,
        relationship: a.relationship,
        delegationNote: a.delegationNote,
        allowedHosts: a.allowedHosts,
        allowedTests: a.allowedTests.map((x) => TEST_LABELS[x] || x),
        allowWriteMethods: a.allowWriteMethods,
        expiresAt: a.expiresAt,
        undertaking: { version: UNDERTAKING_VERSION, clauses: UNDERTAKING_CLAUSES, notice: LEGAL_NOTICE },
        authLimitations: AUTH_LIMITATIONS,
      };
    }, { public: true }],
    ['POST', /^\/api\/confirm\/([\w-]+)$/, async ({ req, m, body }) => {
      rate(req, 'confirm', 20, 3600_000);
      const t = peekToken('authconfirm', m[1]);
      const p = t && data.projects[t.projectId];
      const a = p?.authorization;
      if (!a || a.id !== t.authorizationId || a.revokedAt || a.confirmedAt) throw new HttpError(410, 'This confirmation link is invalid, already used, expired or replaced by a newer authorization.');
      if (body.decision === 'decline') {
        consumeToken('authconfirm', m[1]);
        a.revokedAt = nowIso();
        a.declinedAt = a.revokedAt;
        audit(p, 'authorization.declined', { authorizationId: a.id, by: a.authorizerEmail });
        store.saveNow();
        return { ok: true, declined: true };
      }
      if (!body.accepted) throw bad('Accept the testing undertaking to confirm.');
      if (!typedNameMatches(body.typedName, a.authorizerName)) throw bad(`Type your full name (${a.authorizerName}) to accept the undertaking.`);
      consumeToken('authconfirm', m[1]);
      a.undertaking = { version: UNDERTAKING_VERSION, sha256: hashUndertaking(), acceptedAt: nowIso(), typedName: String(body.typedName).trim(), ip: clientIp(req), userAgent: String(req.headers['user-agent'] || '').slice(0, 200), acceptedVia: 'emailed confirmation link' };
      a.confirmedAt = nowIso();
      a.confirmedVia = `link emailed to ${a.authorizerEmail}`;
      audit(p, 'undertaking.accepted', { authorizationId: a.id, version: UNDERTAKING_VERSION, by: a.authorizerEmail, via: 'email link' });
      audit(p, 'authorization.confirmed', { authorizationId: a.id, by: a.authorizerEmail });
      store.saveNow();
      return { ok: true };
    }, { public: true, limit: 16_384 }],

    // --- meta ---
    ['GET', /^\/api\/meta$/, async () => ({ tests: ALL_TESTS.map((id) => ({ id, label: TEST_LABELS[id] })), limitations: LIMITATIONS, defaults: DEFAULT_CONTROLS, maxAuthorizationDays: MAX_AUTH_DAYS, hardLimits: HARD_LIMITS, undertaking: { version: UNDERTAKING_VERSION, sha256: hashUndertaking(), clauses: UNDERTAKING_CLAUSES, notice: LEGAL_NOTICE }, authLimitations: AUTH_LIMITATIONS, allowLocalTargets: config.allowLocalTargets, allowPrivateTargets: config.allowPrivateTargets })],

    // --- projects ---
    ['GET', /^\/api\/projects$/, async ({ user }) => Object.values(data.projects)
      .filter((p) => memberRole(p, user))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((p) => {
        const scans = Object.values(data.scans).filter((s) => s.projectId === p.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        return { id: p.id, name: p.name, createdAt: p.createdAt, baseUrl: p.target.baseUrl, myRole: memberRole(p, user), authorizedUntil: p.authorization?.revokedAt ? null : p.authorization?.expiresAt, pendingConfirmation: !!p.authorization && !p.authorization.confirmedAt && !p.authorization.revokedAt, lastScan: scans[0] ? scanSummary(scans[0]) : null };
      })],
    ['POST', /^\/api\/projects$/, async ({ body, user }) => {
      const name = String(body.name || '').trim();
      if (!name) throw bad('Project name is required');
      const project = {
        id: newId('prj'),
        name: name.slice(0, 120),
        createdAt: nowIso(),
        members: [{ userId: user.id, role: 'owner', addedAt: nowIso() }],
        authorization: null,
        authorizationHistory: [],
        verifiedHosts: [],
        target: { baseUrl: '', endpoints: [] },
        accounts: [],
        controls: { ...DEFAULT_CONTROLS },
        audit: [],
      };
      audit(project, 'project.created', { by: user.email });
      data.projects[project.id] = project;
      store.saveNow();
      return sanitizeProject(project, user);
    }, { verified: true }],
    ['GET', /^\/api\/projects\/(\w+)$/, async ({ m, user }) => sanitizeProject(getProject(m[1], user), user)],
    // Deleting your own project never needs a verified email: you can always remove what you created.
    ['DELETE', /^\/api\/projects\/(\w+)$/, async ({ m, user }) => {
      const p = getProject(m[1], user);
      ownerOnly(p, user);
      removeProject(p, user.email);
      return { ok: true };
    }],

    ['POST', /^\/api\/projects\/(\w+)\/members$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      ownerOnly(p, user);
      const u = findUserByEmail(body.email);
      // Only existing, active users can be added; nothing is revealed about other addresses.
      if (!u || u.disabledAt) throw bad('No active breakAPI user has that email. Ask an administrator to issue them an account first.');
      if (memberRole(p, u)) throw bad('That user is already a member.');
      p.members.push({ userId: u.id, role: 'member', addedAt: nowIso() });
      audit(p, 'member.added', { email: u.email, by: user.email });
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],
    ['DELETE', /^\/api\/projects\/(\w+)\/members\/(\w+)$/, async ({ m, user }) => {
      const p = getProject(m[1], user);
      const target = p.members.find((x) => x.userId === m[2]);
      if (!target) throw notFound('Member not found');
      if (target.role === 'owner') throw bad('The owner cannot be removed.');
      if (target.userId !== user.id) ownerOnly(p, user); // anyone may leave; only the owner removes others
      p.members = p.members.filter((x) => x !== target);
      audit(p, 'member.removed', { email: data.users[target.userId]?.email, by: user.email });
      store.saveNow();
      return { ok: true };
    }, { verified: true }],

    ['PUT', /^\/api\/projects\/(\w+)\/authorization$/, async ({ req, m, body, user }) => {
      const p = getProject(m[1], user);
      const att = body.attestations || {};
      if (!att.ownsOrAuthorized || !att.scopeAccurate || !att.acceptsImpact) throw bad('All three attestations must be confirmed.');
      const authorizerName = String(body.authorizerName || '').trim();
      const authorizerEmail = normalizeEmail(body.authorizerEmail);
      if (!authorizerName) throw bad('Authorizer name is required.');
      if (!validEmail(authorizerEmail)) throw bad('A valid authorizer email is required.');
      const relationship = body.relationship === 'delegated' ? 'delegated' : 'owner';
      const delegationNote = String(body.delegationNote || '').trim().slice(0, 2000);
      if (relationship === 'delegated' && !delegationNote) throw bad('Describe the delegated authority (who granted it and how it is documented).');
      const allowedHosts = [...new Set((Array.isArray(body.allowedHosts) ? body.allowedHosts : []).map((h) => String(h).trim().toLowerCase()).filter(Boolean))].slice(0, 50);
      if (!allowedHosts.length) throw bad('List at least one host in scope.');
      for (const h of allowedHosts) {
        if (!/^[a-z0-9.-]+(:\d{1,5})?$|^\[[0-9a-f:]+\](:\d{1,5})?$/.test(h)) throw bad(`"${h}" is not a valid host. Use a bare host such as api.example.com or localhost:4010 — no scheme, path or wildcards.`);
      }
      const allowedTests = (Array.isArray(body.allowedTests) ? body.allowedTests : []).filter((t) => ALL_TESTS.includes(t));
      if (!allowedTests.length) throw bad('Authorize at least one test category.');
      const expiresAt = isoOrNull(body.expiresAt, 'Expiry');
      if (!expiresAt || new Date(expiresAt) <= new Date()) throw bad('Expiry must be in the future.');
      if (new Date(expiresAt) - Date.now() > MAX_AUTH_DAYS * 86400_000) throw bad(`Authorizations can last at most ${MAX_AUTH_DAYS} days.`);

      // Who is the test runner, and who is the authorizer? If they are the same verified person, the
      // undertaking is accepted here. If not, the authorizer must confirm from a link sent to their inbox.
      const selfAuthorized = authorizerEmail === user.email;
      const u = body.undertaking || {};
      if (selfAuthorized) {
        if (!u.accepted) throw bad('Accept the testing undertaking to continue.');
        if (!typedNameMatches(u.typedName, authorizerName)) throw bad('Type the authorizer’s full name exactly as entered above to accept the undertaking.');
      }

      if (p.authorization) p.authorizationHistory.push({ ...p.authorization, supersededAt: nowIso() });
      revokeTokens((t) => t.type === 'authconfirm' && t.projectId === p.id);
      const ip = clientIp(req);
      const ua = String(req.headers['user-agent'] || '').slice(0, 200);
      p.authorization = {
        id: newId('auth'),
        authorizerName,
        authorizerEmail,
        authorizerRole: String(body.authorizerRole || '').trim().slice(0, 120),
        relationship,
        delegationNote,
        allowedHosts,
        allowedTests,
        allowWriteMethods: !!body.allowWriteMethods,
        expiresAt,
        attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true },
        recordedAt: nowIso(),
        recordedBy: { userId: user.id, email: user.email, name: user.name, emailVerifiedAt: user.emailVerifiedAt },
        recordedFrom: { ip, userAgent: ua },
        verificationToken: `breakapi-verify-${randomBytes(16).toString('hex')}`,
        undertaking: selfAuthorized ? { version: UNDERTAKING_VERSION, sha256: hashUndertaking(), acceptedAt: nowIso(), typedName: String(u.typedName).trim(), ip, userAgent: ua, acceptedVia: 'recorded by the authorizer (verified account)' } : null,
        confirmedAt: selfAuthorized ? nowIso() : null,
        confirmedVia: selfAuthorized ? 'recorded by the authorizer’s own verified account' : null,
      };
      audit(p, 'authorization.recorded', { authorizationId: p.authorization.id, by: user.email, authorizer: authorizerEmail, hosts: allowedHosts, expiresAt });
      if (selfAuthorized) {
        audit(p, 'undertaking.accepted', { authorizationId: p.authorization.id, version: UNDERTAKING_VERSION, by: authorizerEmail });
      } else {
        const raw = issueToken('authconfirm', { projectId: p.id, authorizationId: p.authorization.id, email: authorizerEmail });
        await sendMail(authorizerEmail, `Confirm security testing of ${allowedHosts.join(', ')}`, `${user.name || user.email} (${user.email}) recorded you, ${authorizerName}, as the person authorizing security tests with breakAPI.\n\nHosts: ${allowedHosts.join(', ')}\nExpires: ${expiresAt}\nWrite requests: ${body.allowWriteMethods ? 'allowed to opted-in endpoints' : 'not allowed'}\n\nNo test runs until you review the scope and accept the undertaking here (the link works once and expires in 72 hours):\n\n${linkBase()}/#/confirm/${raw}\n\nIf you did not authorize this, choose "Decline" on that page or ignore this email; nothing will be tested.\n`);
        audit(p, 'authorization.confirmation_sent', { authorizationId: p.authorization.id, to: authorizerEmail });
      }
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],
    ['POST', /^\/api\/projects\/(\w+)\/authorization\/resend$/, async ({ req, m, user }) => {
      rate(req, 'authresend', 5, 3600_000, user.id);
      const p = getProject(m[1], user);
      const a = p.authorization;
      if (!a || a.confirmedAt || a.revokedAt) throw bad('There is no authorization waiting for confirmation.');
      revokeTokens((t) => t.type === 'authconfirm' && t.projectId === p.id);
      const raw = issueToken('authconfirm', { projectId: p.id, authorizationId: a.id, email: a.authorizerEmail });
      await sendMail(a.authorizerEmail, `Confirm security testing of ${a.allowedHosts.join(', ')}`, `${user.name || user.email} asked you again to confirm the security-testing authorization for ${a.allowedHosts.join(', ')}.\n\n${linkBase()}/#/confirm/${raw}\n\nThe link works once and expires in 72 hours.\n`);
      audit(p, 'authorization.confirmation_sent', { authorizationId: a.id, to: a.authorizerEmail });
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],
    ['POST', /^\/api\/projects\/(\w+)\/authorization\/revoke$/, async ({ m, user }) => {
      const p = getProject(m[1], user);
      if (!p.authorization || p.authorization.revokedAt) throw bad('No active authorization.');
      p.authorization.revokedAt = nowIso();
      revokeTokens((t) => t.type === 'authconfirm' && t.projectId === p.id);
      for (const id of runningScansFor(p.id)) Object.assign(running.get(id), { stopReason: 'Authorization was revoked.', userStopped: true });
      audit(p, 'authorization.revoked', { authorizationId: p.authorization.id, by: user.email });
      purgeCredentials(p, 'authorization revoked');
      store.saveNow();
      return sanitizeProject(p, user);
    }],

    ['PUT', /^\/api\/projects\/(\w+)\/target$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      let url;
      try {
        url = new URL(String(body.baseUrl || '').trim());
      } catch {
        throw bad('Base URL must be an absolute http(s) URL.');
      }
      if (!/^https?:$/.test(url.protocol)) throw bad('Base URL must use http or https.');
      if (url.username || url.password) throw bad('Do not put credentials in the base URL; add a test account instead.');
      p.target.baseUrl = url.href.replace(/\/$/, '');
      audit(p, 'target.updated', { baseUrl: p.target.baseUrl, by: user.email });
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],
    ['POST', /^\/api\/projects\/(\w+)\/import$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      let result;
      try {
        result = importSpec(body.format, String(body.content || ''));
      } catch (err) {
        throw bad(err.message);
      }
      if (!result.endpoints.length) throw bad('No endpoints were found in the import.');
      if (result.endpoints.length > 2000) throw bad('That import has more than 2000 endpoints; split it into smaller projects.');
      const existing = new Map(p.target.endpoints.map((e) => [e.id, e]));
      const incoming = result.endpoints.map((e) => (existing.has(e.id) && !body.replace ? existing.get(e.id) : e));
      p.target.endpoints = body.replace ? incoming : [...new Map([...p.target.endpoints, ...incoming].map((e) => [e.id, e])).values()];
      if (!p.target.baseUrl && result.baseUrl) p.target.baseUrl = result.baseUrl.replace(/\/$/, '');
      audit(p, 'endpoints.imported', { format: body.format, count: result.endpoints.length, by: user.email });
      store.saveNow();
      return { ...sanitizeProject(p, user), imported: result.endpoints.length, suggestedBaseUrl: result.baseUrl };
    }, { verified: true }],
    ['PATCH', /^\/api\/projects\/(\w+)\/endpoints\/(\w+)$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      const ep = p.target.endpoints.find((e) => e.id === m[2]);
      if (!ep) throw notFound('Endpoint not found');
      for (const k of ['enabled', 'requiresAuth', 'adminOnly', 'syntheticWrites']) if (k in body) ep[k] = !!body[k];
      if ('syntheticWrites' in body) audit(p, ep.syntheticWrites ? 'endpoint.synthetic_writes_enabled' : 'endpoint.synthetic_writes_disabled', { endpoint: `${ep.method} ${ep.path}`, by: user.email });
      store.save();
      return ep;
    }, { verified: true }],
    ['DELETE', /^\/api\/projects\/(\w+)\/endpoints$/, async ({ m, user }) => {
      const p = getProject(m[1], user);
      p.target.endpoints = [];
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],

    ['POST', /^\/api\/projects\/(\w+)\/verify$/, async ({ req, m, body, user }) => {
      rate(req, 'verify', 30, 15 * 60_000, user.id);
      const p = getProject(m[1], user);
      if (!p.authorization || p.authorization.revokedAt) throw bad('Record an authorization first; its hosts are what get verified.');
      const entry = String(body.host || '').trim().toLowerCase();
      if (!p.authorization.allowedHosts.includes(entry)) throw bad(`"${entry}" is not one of the hosts in the authorization.`);
      if (isLocalEntry(entry)) throw bad(`"${entry}" is local development only and needs no verification.`);
      const result = await verifyEntry(p, entry);
      if (!result.ok) throw bad(result.error);
      return sanitizeProject(p, user);
    }, { verified: true }],

    ['POST', /^\/api\/projects\/(\w+)\/accounts$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      const label = String(body.label || '').trim();
      const secret = String(body.secret || '').trim();
      if (!label) throw bad('Account label is required.');
      if (!secret) throw bad('A credential is required.');
      if (secret.length > 8192) throw bad('That credential is too long.');
      if (p.accounts.some((a) => a.label === label)) throw bad('Account labels must be unique.');
      if (p.accounts.length >= 20) throw bad('A project can have at most 20 test accounts.');
      const authType = ['bearer', 'header', 'cookie'].includes(body.authType) ? body.authType : 'bearer';
      const headerName = String(body.headerName || '').trim();
      if (authType === 'header' && !/^[A-Za-z0-9-]{1,64}$/.test(headerName)) throw bad('Header name is required for header authentication.');
      const resourceIds = Object.create(null);
      for (const [k, v] of Object.entries(body.resourceIds && typeof body.resourceIds === 'object' ? body.resourceIds : {}).slice(0, 20)) {
        if (/^[\w.-]{1,64}$/.test(String(k).trim()) && String(v).trim()) resourceIds[String(k).trim()] = String(v).trim().slice(0, 200);
      }
      const account = {
        id: newId('acct'),
        label: label.slice(0, 60),
        role: body.role === 'admin' ? 'admin' : 'user',
        authType,
        headerName: authType === 'header' ? headerName : undefined,
        secretEnc: encrypt(key, authType === 'bearer' ? secret.replace(/^Bearer\s+/i, '') : secret),
        secretHint: mask(secret),
        resourceIds: { ...resourceIds },
        createdAt: nowIso(),
      };
      p.accounts.push(account);
      audit(p, 'account.added', { label: account.label, role: account.role, by: user.email });
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],
    ['DELETE', /^\/api\/projects\/(\w+)\/accounts\/(\w+)$/, async ({ m, user }) => {
      const p = getProject(m[1], user);
      const a = p.accounts.find((x) => x.id === m[2]);
      if (!a) throw notFound('Account not found');
      p.accounts = p.accounts.filter((x) => x !== a);
      audit(p, 'account.deleted', { label: a.label, by: user.email });
      store.saveNow();
      return sanitizeProject(p, user);
    }],
    ['DELETE', /^\/api\/projects\/(\w+)\/credentials$/, async ({ m, user }) => {
      const p = getProject(m[1], user);
      purgeCredentials(p, `purged by ${user.email}`);
      store.saveNow();
      return sanitizeProject(p, user);
    }],

    ['PUT', /^\/api\/projects\/(\w+)\/controls$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      const d = DEFAULT_CONTROLS;
      const c = {
        maxRequests: Math.round(clamp(body.maxRequests, 10, HARD_LIMITS.maxRequests, d.maxRequests)),
        rps: clamp(body.rps, 0.5, HARD_LIMITS.rps, d.rps),
        burstRps: clamp(body.burstRps, 1, HARD_LIMITS.burstRps, d.burstRps),
        rateLimitBurst: Math.round(clamp(body.rateLimitBurst, 5, 500, d.rateLimitBurst)),
        timeoutMs: Math.round(clamp(body.timeoutMs, 1000, 60000, d.timeoutMs)),
        stopOnErrorStreak: Math.round(clamp(body.stopOnErrorStreak, 1, 100, d.stopOnErrorStreak)),
        exclusions: (Array.isArray(body.exclusions) ? body.exclusions : String(body.exclusions || '').split('\n')).map((s) => String(s).trim().slice(0, 300)).filter(Boolean).slice(0, 200),
        windowStart: isoOrNull(body.windowStart, 'Window start'),
        windowEnd: isoOrNull(body.windowEnd, 'Window end'),
        monitoringContact: String(body.monitoringContact || '').trim().slice(0, 200),
        maxWrites: Math.round(clamp(body.maxWrites, 0, HARD_LIMITS.maxWrites, d.maxWrites)),
        maxDurationMs: Math.round(clamp(body.maxDurationMs, 60_000, HARD_LIMITS.maxDurationMs, d.maxDurationMs)),
      };
      if (c.windowStart && c.windowEnd && c.windowEnd <= c.windowStart) throw bad('Window end must be after window start.');
      p.controls = c;
      audit(p, 'controls.updated', { by: user.email });
      store.saveNow();
      return sanitizeProject(p, user);
    }, { verified: true }],

    ['GET', /^\/api\/projects\/(\w+)\/scans$/, async ({ m, user }) => {
      getProject(m[1], user);
      return Object.values(data.scans).filter((s) => s.projectId === m[1]).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(scanSummary);
    }],
    ['POST', /^\/api\/projects\/(\w+)\/scans$/, async ({ m, body, user }) => {
      const p = getProject(m[1], user);
      if (body.previousScanId) getScan(body.previousScanId, user);
      return scanSummary(await startScan(p, user, body.previousScanId));
    }, { verified: true }],
    ['GET', /^\/api\/projects\/(\w+)\/audit$/, async ({ m, user }) => getProject(m[1], user).audit],

    ['GET', /^\/api\/scans\/(\w+)$/, async ({ m, user }) => {
      const s = getScan(m[1], user);
      const ctl = running.get(s.id);
      return { ...s, log: s.log.slice(-300), paused: !!ctl?.paused, project: { id: s.projectId, name: data.projects[s.projectId]?.name, maxRequests: (s.controlsSnapshot || data.projects[s.projectId]?.controls)?.maxRequests } };
    }],
    ['POST', /^\/api\/scans\/(\w+)\/(pause|resume|stop)$/, async ({ m, user }) => {
      const s = getScan(m[1], user);
      const ctl = running.get(s.id);
      if (!ctl) throw new HttpError(409, 'Scan is not running.');
      const p = data.projects[s.projectId];
      if (m[2] === 'pause') {
        ctl.paused = true;
        s.status = 'paused';
      } else if (m[2] === 'resume') {
        ctl.paused = false;
        s.status = 'running';
      } else {
        Object.assign(ctl, { stopReason: `Stopped by ${user.email}.`, userStopped: true });
      }
      audit(p, `scan.${m[2]}`, { scanId: s.id, by: user.email });
      store.save();
      return { ok: true };
    }],
    ['POST', /^\/api\/scans\/(\w+)\/rerun$/, async ({ m, user }) => {
      const s = getScan(m[1], user);
      return scanSummary(await startScan(getProject(s.projectId, user), user, s.id));
    }, { verified: true }],
    ['GET', /^\/api\/scans\/(\w+)\/report\.json$/, async ({ res, m, user }) => {
      const s = getScan(m[1], user);
      const p = data.projects[s.projectId];
      res.setHeader('content-disposition', `attachment; filename="breakapi-${s.id}.json"`);
      return {
        generatedAt: nowIso(),
        project: { id: p.id, name: p.name },
        authorization: s.authorizationSnapshot ? { ...s.authorizationSnapshot, verificationToken: undefined } : null,
        controls: s.controlsSnapshot,
        target: s.targetSnapshot,
        scan: { ...s, log: undefined, authorizationSnapshot: undefined, controlsSnapshot: undefined },
        limitations: LIMITATIONS,
        authLimitations: AUTH_LIMITATIONS,
      };
    }],
  ];

  const sameOrigin = (req) => {
    const origin = req.headers.origin;
    if (!origin) return true;
    if (config.publicUrl && origin === new URL(config.publicUrl).origin) return true;
    return origin === `http://${req.headers.host}` || origin === `https://${req.headers.host}`;
  };

  server = http.createServer(async (req, res) => {
    const started = Date.now();
    let userId;
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    if (secureCookies(req)) res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
    res.on('finish', () => {
      if (config.quiet) return;
      log.info?.(JSON.stringify({ t: new Date().toISOString(), method: req.method, path: (req.url || '').split('?')[0], status: res.statusCode, ms: Date.now() - started, user: userId, ip: clientIp(req) }));
    });
    let url;
    try {
      url = new URL(req.url, 'http://local');
    } catch {
      res.writeHead(400);
      return res.end();
    }
    try {
      // Embedded simulation: sandbox traffic only, answered with the sim's own headers (not breakAPI's).
      if (config.simEmbedDir && (url.pathname === SIM_PREFIX || url.pathname.startsWith(`${SIM_PREFIX}/`))) {
        for (const k of Object.keys(SECURITY_HEADERS)) res.removeHeader(k);
        res.removeHeader('strict-transport-security');
        if (!embedded) {
          res.writeHead(503, { 'content-type': 'application/json; charset=utf-8' });
          return res.end(JSON.stringify({ error: { code: 'unavailable', message: 'The simulation is starting or unavailable.' } }));
        }
        return embedded.forward(req, res, url);
      }
      if (req.method === 'GET' && STATIC[url.pathname]) {
        const [file, type] = STATIC[url.pathname];
        res.writeHead(200, { 'content-type': type, ...(STATIC_CACHE[url.pathname] ? { 'cache-control': 'public, max-age=604800, immutable' } : {}) });
        return res.end(readFileSync(join(PUBLIC_DIR, file)));
      }
      let m;
      if (req.method === 'GET' && config.lab && (m = url.pathname.match(/^\/reports\/lab\/([\w-]+)\/(\d+)$/))) {
        const r = lab.reportData(m[1], Number(m[2]));
        if (!r) throw notFound('This run is no longer available.');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(renderReport(r.project, r.scan));
      }
      if (req.method === 'GET' && (m = url.pathname.match(/^\/reports\/(\w+)$/))) {
        const s = sessionFor(req);
        if (!s) {
          res.writeHead(302, { location: '/#/' });
          return res.end();
        }
        userId = s.user.id;
        const scan = getScan(m[1], s.user);
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(renderReport(data.projects[scan.projectId], scan));
      }
      for (const [method, re, handler, opts = {}] of routes) {
        if (req.method !== method || !(m = url.pathname.match(re))) continue;
        let user = null;
        let session = null;
        if (!opts.public) {
          const s = sessionFor(req);
          if (!s) throw new HttpError(401, 'Sign in required');
          user = s.user;
          session = { ...s.session, hash: s.hash };
          userId = user.id;
          if (opts.admin && user.role !== 'admin') throw new HttpError(403, 'Administrators only.');
          if (opts.verified && !user.emailVerifiedAt) throw new HttpError(403, 'Verify your email address first. Check your inbox, or resend the link from your account page.', { code: 'email_unverified' });
        }
        // CSRF: browsers cannot add custom headers cross-origin without a CORS preflight we never grant;
        // the Origin check is a second, independent layer.
        if (method !== 'GET') {
          if (req.headers['x-breakapi'] !== '1') throw new HttpError(403, 'Missing X-BreakAPI header');
          if (!sameOrigin(req)) throw new HttpError(403, 'Cross-origin request refused');
        }
        const body = method === 'GET' ? {} : await readBody(req, opts.limit || 5 * 1024 * 1024);
        const result = await handler({ req, res, m, body, user, session });
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        return res.end(JSON.stringify(result));
      }
      throw notFound();
    } catch (err) {
      const status = err.status || 500;
      if (status === 500) log.error?.(err);
      if (!res.headersSent) {
        const headers = { 'content-type': 'application/json; charset=utf-8' };
        if (err.extra?.retryAfter) headers['retry-after'] = String(err.extra.retryAfter);
        res.writeHead(status, headers);
      }
      res.end(JSON.stringify({ error: status === 500 ? 'Internal error' : err.message, ...(err.extra?.code ? { code: err.extra.code } : {}) }));
    }
  });

  /** Stops running scans and flushes the store; used for graceful shutdown and tests. */
  const shutdown = async (reason = 'The breakAPI server is shutting down.') => {
    for (const ctl of running.values()) ctl.stopReason ??= reason;
    const labDone = lab.shutdown();
    const deadline = Date.now() + 5000;
    while (running.size && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    clearInterval(sweeper);
    limiter.stop();
    store.saveNow();
    // Sandboxes are deleted by the lab; then the embedded sim (if any) is stopped.
    await labDone.catch(() => {});
    const simServer = embedded;
    embedded = null; // later /sim requests answer 503 instead of reaching a closed port
    await simServer?.close();
  };

  server.on('close', () => {
    clearInterval(sweeper);
    limiter.stop();
  });
  return { server, store, config, mailer, key, setupToken: () => setupToken, lab, ready, shutdown, decrypt: (blob) => decrypt(key, blob) };
}
