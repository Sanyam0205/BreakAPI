import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { loadConfig, configProblems } from '../src/config.js';
import { classifyAddress, safeFetch, addressRefusal } from '../src/netguard.js';
import { passwordProblem } from '../src/auth.js';
import { createDemoServer } from '../demo/vulnerable-api.js';
import { sleep } from '../src/util.js';

const quiet = { info() {}, error() {} };
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const PASSWORD = 'correct-horse-staple-42';
const inDays = (d) => new Date(Date.now() + d * 86400_000).toISOString();

/** Starts an app on a temp dir. Returns helpers bound to it. */
async function startApp(overrides = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'breakapi-auth-'));
  const app = createApp({ config: loadConfig({}, { dataDir, quiet: true, ...overrides }), log: quiet });
  const base = `http://127.0.0.1:${await listen(app.server)}`;
  const outbox = () => app.mailer.readOutbox();
  const lastLink = (kind) => {
    const all = outbox().join('\n');
    const links = [...all.matchAll(new RegExp(`/#/${kind}/([\\w-]+)`, 'g'))];
    return links.length ? links[links.length - 1][1] : null;
  };
  /** A browser-like client with its own cookie. */
  const client = () => {
    let sid = '';
    const call = async (method, path, body, { csrf = true, headers = {} } = {}) => {
      const h = { 'content-type': 'application/json', ...headers };
      if (sid) h.cookie = `bp_sid=${sid}`;
      if (csrf) h['x-breakapi'] = '1';
      const r = await fetch(base + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
      const set = r.headers.get('set-cookie');
      if (set) sid = (set.match(/bp_sid=([^;]*)/) || [])[1] || '';
      const text = await r.text();
      let json;
      try { json = JSON.parse(text); } catch { json = text; }
      return { status: r.status, body: json, setCookie: set, headers: r.headers };
    };
    return { call, get sid() { return sid; }, set sid(v) { sid = v; } };
  };
  const stop = () => {
    app.server.close();
    rmSync(dataDir, { recursive: true, force: true });
  };
  return { app, base, outbox, lastLink, client, stop, dataDir };
}

let env;
let admin;
let umaToken;

before(async () => {
  env = await startApp();
  admin = env.client();
});
after(() => env.stop());

test('first-run setup needs the setup token, creates a verified admin once', async () => {
  const me = await admin.call('GET', '/api/auth/me');
  assert.equal(me.body.setupRequired, true);
  assert.equal(me.body.user, null);
  const wrong = await admin.call('POST', '/api/auth/setup', { setupToken: 'nope', name: 'Ada Admin', email: 'ada@example.com', password: PASSWORD });
  assert.equal(wrong.status, 403);
  const weak = await admin.call('POST', '/api/auth/setup', { setupToken: env.app.setupToken(), name: 'Ada Admin', email: 'ada@example.com', password: 'short' });
  assert.equal(weak.status, 400);
  const ok = await admin.call('POST', '/api/auth/setup', { setupToken: env.app.setupToken(), name: 'Ada Admin', email: 'Ada@Example.com', password: PASSWORD });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.user.role, 'admin');
  assert.equal(ok.body.user.email, 'ada@example.com');
  assert.equal(ok.body.user.emailVerified, true);
  assert.match(ok.setCookie, /HttpOnly/);
  assert.match(ok.setCookie, /SameSite=Strict/);
  const again = await env.client().call('POST', '/api/auth/setup', { setupToken: 'anything', name: 'X', email: 'x@example.com', password: PASSWORD });
  assert.equal(again.status, 409);
  assert.equal((await admin.call('GET', '/api/auth/me')).body.setupRequired, false);
  // The raw session id is never stored, only its hash.
  assert.ok(!readFileSync(join(env.dataDir, 'db.json'), 'utf8').includes(admin.sid));
});

test('login is generic on failure, rotates the session, and logout ends it', async () => {
  const c = env.client();
  const wrong = await c.call('POST', '/api/auth/login', { email: 'ada@example.com', password: 'wrong-password-value' });
  const unknown = await c.call('POST', '/api/auth/login', { email: 'nobody@example.com', password: 'wrong-password-value' });
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.equal(wrong.body.error, unknown.body.error, 'no account enumeration through login');
  const ok = await c.call('POST', '/api/auth/login', { email: 'ADA@example.com', password: PASSWORD });
  assert.equal(ok.status, 200);
  const first = c.sid;
  await c.call('POST', '/api/auth/login', { email: 'ada@example.com', password: PASSWORD });
  assert.notEqual(c.sid, first, 'a new session id on every login');
  const stale = env.client();
  stale.sid = first;
  assert.equal((await stale.call('GET', '/api/projects')).status, 401, 'the old session was dropped');
  assert.equal((await c.call('GET', '/api/projects')).status, 200);
  const keep = c.sid;
  await c.call('POST', '/api/auth/logout');
  const reuse = env.client();
  reuse.sid = keep;
  assert.equal((await reuse.call('GET', '/api/projects')).status, 401);
});

test('login is rate-limited per account', async () => {
  const c = env.client();
  let last;
  for (let i = 0; i < 9; i++) last = await c.call('POST', '/api/auth/login', { email: 'ratelimit@example.com', password: `guess-number-${i}` });
  assert.equal(last.status, 429);
  assert.ok(Number(last.headers.get('retry-after')) > 0);
});

test('admins issue users; users cannot use admin routes', async () => {
  const inv = await admin.call('POST', '/api/admin/users', { email: 'uma@example.com', name: 'Uma User', password: PASSWORD });
  assert.equal(inv.status, 200);
  assert.equal(inv.body.user.role, 'user');
  assert.equal(inv.body.user.emailVerified, true);
  umaToken = inv.body.credentials.setupToken;
  assert.equal((await admin.call('POST', '/api/admin/users', { email: 'uma@example.com' })).status, 409);
  assert.equal(env.outbox().length, 0, 'the admin shares the details; nothing is emailed');
  const u = env.client();
  assert.equal((await u.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken })).status, 200);
  for (const path of ['/api/admin/users', '/api/admin/overview', '/api/admin/audit']) {
    assert.equal((await u.call('GET', path)).status, 403, path);
  }
  const list = await admin.call('GET', '/api/admin/users');
  assert.ok(list.body.some((x) => x.email === 'uma@example.com' && x.accessExpiresAt && !x.accessEnded));
  const leaked = JSON.stringify(list.body);
  assert.ok(!leaked.includes('passwordHash') && !leaked.includes('tokenHash') && !leaked.includes(umaToken));
});

test('projects are private to their members; owners manage membership', async () => {
  const uma = env.client();
  await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken });
  const { body: p } = await admin.call('POST', '/api/projects', { name: 'admin-only project' });
  assert.equal((await uma.call('GET', `/api/projects/${p.id}`)).status, 404, 'non-members get 404, not 403');
  assert.ok(!(await uma.call('GET', '/api/projects')).body.some((x) => x.id === p.id));
  assert.equal((await admin.call('POST', `/api/projects/${p.id}/members`, { email: 'ghost@example.com' })).status, 400);
  assert.equal((await admin.call('POST', `/api/projects/${p.id}/members`, { email: 'uma@example.com' })).status, 200);
  const seen = await uma.call('GET', `/api/projects/${p.id}`);
  assert.equal(seen.status, 200);
  assert.equal(seen.body.myRole, 'member');
  assert.equal((await uma.call('DELETE', `/api/projects/${p.id}`)).status, 403, 'members cannot delete');
  assert.equal((await uma.call('POST', `/api/projects/${p.id}/members`, { email: 'ada@example.com' })).status, 403);
  const me = (await uma.call('GET', '/api/auth/me')).body.user;
  assert.equal((await uma.call('DELETE', `/api/projects/${p.id}/members/${me.id}`)).status, 200, 'members may leave');
  assert.equal((await uma.call('GET', `/api/projects/${p.id}`)).status, 404);
  // Report pages also need membership.
  const r = await fetch(`${env.base}/reports/scan_doesnotexist`, { headers: { cookie: `bp_sid=${uma.sid}` }, redirect: 'manual' });
  assert.equal(r.status, 404);
  const anon = await fetch(`${env.base}/reports/scan_x`, { redirect: 'manual' });
  assert.equal(anon.status, 302);
});

test('an authorization for someone else waits for that person to confirm by email', async () => {
  const demo = createDemoServer();
  const host = `localhost:${await listen(demo)}`;
  try {
    const { body: p } = await admin.call('POST', '/api/projects', { name: 'delegated' });
    const rec = await admin.call('PUT', `/api/projects/${p.id}/authorization`, {
      authorizerName: 'Olu Owner', authorizerEmail: 'olu@example.com', relationship: 'owner',
      allowedHosts: [host], allowedTests: ['config'], expiresAt: inDays(3),
      attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true },
    });
    assert.equal(rec.status, 200, JSON.stringify(rec.body));
    assert.equal(rec.body.authorization.confirmedAt, null);
    assert.equal(rec.body.authorization.recordedBy.email, 'ada@example.com');
    assert.ok(rec.body.problems.some((x) => /Waiting for olu@example.com/.test(x)));
    await admin.call('POST', `/api/projects/${p.id}/import`, { format: 'manual', content: 'GET /api/health public' });
    await admin.call('PUT', `/api/projects/${p.id}/target`, { baseUrl: `http://${host}` });
    assert.equal((await admin.call('POST', `/api/projects/${p.id}/scans`, {})).status, 422);

    const token = env.lastLink('confirm');
    assert.ok(env.outbox().some((m) => /To: olu@example.com/.test(m)), 'email went to the authorizer');
    const anon = env.client(); // the authorizer needs no breakAPI account
    const view = await anon.call('GET', `/api/confirm/${token}`);
    assert.equal(view.status, 200);
    assert.deepEqual(view.body.allowedHosts, [host]);
    assert.equal(view.body.recordedBy.email, 'ada@example.com');
    assert.ok(view.body.undertaking.clauses.length >= 5);
    assert.equal((await anon.call('POST', `/api/confirm/${token}`, { accepted: true, typedName: 'Ada Admin' })).status, 400, 'must type the authorizer name');
    const ok = await anon.call('POST', `/api/confirm/${token}`, { accepted: true, typedName: 'olu owner' });
    assert.equal(ok.status, 200);
    assert.equal((await anon.call('POST', `/api/confirm/${token}`, { accepted: true, typedName: 'Olu Owner' })).status, 410, 'one use only');

    const after = (await admin.call('GET', `/api/projects/${p.id}`)).body;
    assert.ok(after.authorization.confirmedAt);
    assert.match(after.authorization.confirmedVia, /olu@example.com/);
    assert.equal(after.authorization.undertaking.acceptedVia, 'emailed confirmation link');
    const start = await admin.call('POST', `/api/projects/${p.id}/scans`, {});
    assert.equal(start.status, 200, JSON.stringify(start.body));
    let scan;
    for (let i = 0; i < 100; i++) {
      scan = (await admin.call('GET', `/api/scans/${start.body.id}`)).body;
      if (!['queued', 'running'].includes(scan.status)) break;
      await sleep(100);
    }
    assert.equal(scan.status, 'completed');
    assert.equal(scan.startedBy.email, 'ada@example.com');
    const report = await fetch(`${env.base}/reports/${scan.id}`, { headers: { cookie: `bp_sid=${admin.sid}` } });
    const html = await report.text();
    assert.match(html, /Started by/);
    assert.match(html, /link emailed to olu@example.com/);

    // A newer authorization makes old links useless, and the authorizer can decline.
    await admin.call('PUT', `/api/projects/${p.id}/authorization`, {
      authorizerName: 'Olu Owner', authorizerEmail: 'olu@example.com', allowedHosts: [host], allowedTests: ['config'], expiresAt: inDays(3),
      attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true },
    });
    const first = env.lastLink('confirm');
    await admin.call('POST', `/api/projects/${p.id}/authorization/resend`);
    const second = env.lastLink('confirm');
    assert.notEqual(first, second);
    assert.equal((await anon.call('GET', `/api/confirm/${first}`)).status, 410, 'resending replaces the old link');
    assert.equal((await anon.call('POST', `/api/confirm/${second}`, { decision: 'decline' })).status, 200);
    const declined = (await admin.call('GET', `/api/projects/${p.id}`)).body;
    assert.ok(declined.authorization.revokedAt && declined.authorization.declinedAt);
  } finally {
    demo.close();
  }
});

test('forgot/reset: same answer for unknown accounts; reset signs out other sessions', async () => {
  const c = env.client();
  const unknown = await c.call('POST', '/api/auth/forgot', { email: 'nobody@example.com' });
  const known = await c.call('POST', '/api/auth/forgot', { email: 'uma@example.com' });
  assert.equal(unknown.body.message, known.body.message);
  const uma = env.client();
  await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken });
  const token = env.lastLink('reset');
  assert.equal((await c.call('POST', '/api/auth/reset', { token, password: 'weak' })).status, 400);
  assert.equal((await c.call('POST', '/api/auth/reset', { token, password: 'a-brand-new-passphrase' })).status, 200);
  assert.equal((await c.call('POST', '/api/auth/reset', { token, password: 'another-new-passphrase' })).status, 410);
  assert.equal((await uma.call('GET', '/api/projects')).status, 401, 'existing sessions ended');
  assert.equal((await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken })).status, 401);
  assert.equal((await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: 'a-brand-new-passphrase', setupToken: umaToken })).status, 200);
  assert.equal((await uma.call('POST', '/api/auth/password', { current: 'wrong-current-pass', password: 'yet-another-passphrase' })).status, 400);
  assert.equal((await uma.call('POST', '/api/auth/password', { current: 'a-brand-new-passphrase', password: PASSWORD })).status, 200);
  assert.equal((await uma.call('GET', '/api/projects')).status, 200, 'changing the password keeps this session signed in');
  const sessions = (await uma.call('GET', '/api/auth/sessions')).body;
  assert.equal(sessions.filter((x) => x.current).length, 1);
});

test('admins disable users (sessions end), and the last admin cannot be removed', async () => {
  const uma = env.client();
  await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken });
  const users = (await admin.call('GET', '/api/admin/users')).body;
  const umaId = users.find((x) => x.email === 'uma@example.com').id;
  const adaId = users.find((x) => x.email === 'ada@example.com').id;
  assert.equal((await admin.call('PATCH', `/api/admin/users/${umaId}`, { disabled: true })).status, 200);
  assert.equal((await uma.call('GET', '/api/projects')).status, 401);
  assert.equal((await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken })).status, 401);
  assert.equal((await admin.call('PATCH', `/api/admin/users/${adaId}`, { role: 'user' })).status, 400, 'last admin keeps the role');
  assert.equal((await admin.call('PATCH', `/api/admin/users/${adaId}`, { disabled: true })).status, 400);
  assert.equal((await admin.call('DELETE', `/api/admin/users/${adaId}`)).status, 400);
  assert.equal((await admin.call('PATCH', `/api/admin/users/${umaId}`, { disabled: false })).status, 200);
  assert.equal((await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: umaToken })).status, 200);
  assert.equal((await admin.call('PATCH', `/api/admin/users/${umaId}`, { role: 'admin' })).status, 200);
  assert.equal((await uma.call('GET', '/api/projects')).status, 401, 'a role change ends their sessions');
  assert.equal((await uma.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD })).status, 200, 'admins need no setup token');
  assert.equal((await uma.call('GET', '/api/admin/overview')).status, 200, 'promoted user can use admin routes');
  const audit = (await admin.call('GET', '/api/admin/audit')).body;
  assert.ok(audit.some((e) => e.event === 'user.disabled') && audit.some((e) => e.event === 'user.role_changed'));
});

test('cross-origin writes and prototype pollution are refused', async () => {
  const x = await admin.call('POST', '/api/projects', { name: 'csrf' }, { headers: { origin: 'https://evil.example' } });
  assert.equal(x.status, 403);
  const { body: p } = await admin.call('POST', '/api/projects', { name: 'proto' });
  const raw = await fetch(`${env.base}/api/projects/${p.id}/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-breakapi': '1', cookie: `bp_sid=${admin.sid}` },
    body: '{"label":"p","secret":"tok-123456789","resourceIds":{"__proto__":{"polluted":"yes"},"id":"1"}}',
  });
  assert.equal(raw.status, 200);
  assert.equal({}.polluted, undefined);
});

test('an unverified account cannot test until its email is verified; sign-up and invite links are gone', async () => {
  const e = await startApp();
  try {
    const root = e.client();
    await root.call('POST', '/api/auth/setup', { setupToken: e.app.setupToken(), name: 'Root', email: 'root@example.com', password: PASSWORD });
    const { body: issued } = await root.call('POST', '/api/admin/users', { email: 'sid@example.com', name: 'Sid', password: PASSWORD });
    const c = e.client();
    await c.call('POST', '/api/auth/login', { email: 'sid@example.com', password: PASSWORD, setupToken: issued.credentials.setupToken });
    // Accounts from before this rule can still be unverified.
    Object.values(e.app.store.data.users).find((u) => u.email === 'sid@example.com').emailVerifiedAt = null;
    const blocked = await c.call('POST', '/api/projects', { name: 'too early' });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.code, 'email_unverified');
    assert.equal((await c.call('POST', '/api/auth/resend-verification')).status, 200);
    const token = e.lastLink('verify');
    assert.equal((await c.call('POST', '/api/auth/verify', { token })).status, 200);
    assert.equal((await c.call('POST', '/api/auth/verify', { token })).status, 410);
    assert.equal((await c.call('POST', '/api/projects', { name: 'now ok' })).status, 200);
    assert.equal((await e.client().call('POST', '/api/auth/signup', { name: 'N', email: 'n@example.com', password: PASSWORD })).status, 404);
    assert.equal((await e.client().call('POST', '/api/auth/invite/accept', { token: 'x', name: 'N', password: PASSWORD })).status, 404);
  } finally {
    e.stop();
  }
});

test('production config: refuses unsafe settings and local or private targets', async () => {
  const prod = loadConfig({ BREAKAPI_ENV: 'production' });
  assert.equal(prod.allowLocalTargets, false);
  assert.equal(prod.allowPrivateTargets, false);
  assert.equal(prod.host, '0.0.0.0');
  assert.equal(configProblems(prod).length, 3);
  const good = loadConfig({ BREAKAPI_ENV: 'production', BREAKAPI_PUBLIC_URL: 'https://breakapi.example.com', BREAKAPI_SECRET_KEY: Buffer.alloc(32, 7).toString('base64'), SMTP_HOST: 'smtp.example.com' });
  assert.deepEqual(configProblems(good), []);

  assert.equal(classifyAddress('127.0.0.1'), 'loopback');
  assert.equal(classifyAddress('10.1.2.3'), 'private');
  assert.equal(classifyAddress('192.168.0.9'), 'private');
  assert.equal(classifyAddress('172.20.0.1'), 'private');
  assert.equal(classifyAddress('169.254.169.254'), 'metadata');
  assert.equal(classifyAddress('::ffff:10.0.0.1'), 'private');
  assert.equal(classifyAddress('8.8.8.8'), 'public');
  assert.ok(addressRefusal('127.0.0.1', prod));
  assert.ok(addressRefusal('10.0.0.1', prod));
  assert.equal(addressRefusal('8.8.8.8', prod), null);

  // The guard runs inside DNS resolution, so a name that resolves to loopback is refused too.
  const demo = createDemoServer();
  const port = await listen(demo);
  try {
    await assert.rejects(safeFetch(`http://localhost:${port}/api/health`, { config: prod }), (e) => e.code === 'EBREAKAPI_BLOCKED');
    const okRes = await safeFetch(`http://localhost:${port}/api/health`, { config: loadConfig({}) });
    assert.equal(okRes.status, 200);
  } finally {
    demo.close();
  }

  const p = await startApp({ allowLocalTargets: false, allowPrivateTargets: false });
  try {
    const a = p.client();
    await a.call('POST', '/api/auth/setup', { setupToken: p.app.setupToken(), name: 'Pat Prod', email: 'pat@example.com', password: PASSWORD });
    const { body: proj } = await a.call('POST', '/api/projects', { name: 'local target' });
    const rec = await a.call('PUT', `/api/projects/${proj.id}/authorization`, {
      authorizerName: 'Pat Prod', authorizerEmail: 'pat@example.com', allowedHosts: ['localhost:4010', '10.0.0.5'], allowedTests: ['config'], expiresAt: inDays(1),
      attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true }, undertaking: { accepted: true, typedName: 'Pat Prod' },
    });
    assert.ok(rec.body.problems.some((x) => /localhost:4010" cannot be tested from this server/.test(x)));
    assert.ok(rec.body.problems.some((x) => /10\.0\.0\.5" cannot be tested from this server/.test(x)));
    assert.equal((await a.call('POST', `/api/projects/${proj.id}/verify`, { host: '10.0.0.5' })).status, 400);
  } finally {
    p.stop();
  }
});

test('password policy and health endpoints', async () => {
  assert.ok(passwordProblem('short'));
  assert.ok(passwordProblem('password1234'.slice(0, 8)));
  assert.ok(passwordProblem('aaaaaaaaaaaaaaaa'));
  assert.ok(passwordProblem('ada-lovelace-2026', 'ada-lovelace@example.com'));
  assert.equal(passwordProblem('violet-otter-harbour-9'), null);
  for (const path of ['/healthz', '/api/healthz']) {
    const h = await fetch(`${env.base}${path}`);
    assert.equal(h.status, 200, path);
    assert.equal((await h.json()).ok, true);
  }
  for (const path of ['/readyz', '/api/readyz']) assert.equal((await fetch(`${env.base}${path}`)).status, 200, path);
  const page = await fetch(`${env.base}/`);
  assert.match(page.headers.get('content-security-policy'), /object-src 'none'/);
});

test('SMTP delivery speaks the protocol (AUTH, MAIL, RCPT, DATA with dot-stuffing)', async () => {
  const net = await import('node:net');
  const { createMailer } = await import('../src/mail.js');
  const seen = [];
  let data = '';
  const smtp = net.createServer((sock) => {
    let inData = false;
    let buf = '';
    sock.write('220 fake ESMTP\r\n');
    sock.on('data', (d) => {
      buf += d.toString();
      if (inData) {
        if (buf.includes('\r\n.\r\n')) {
          data = buf.split('\r\n.\r\n')[0];
          buf = '';
          inData = false;
          sock.write('250 queued\r\n');
        }
        return;
      }
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        seen.push(line);
        if (/^EHLO/.test(line)) sock.write('250-fake\r\n250 AUTH PLAIN\r\n');
        else if (/^AUTH PLAIN/.test(line)) sock.write('235 ok\r\n');
        else if (/^(MAIL|RCPT)/.test(line)) sock.write('250 ok\r\n');
        else if (line === 'DATA') { inData = true; sock.write('354 go\r\n'); }
        else if (line === 'QUIT') { sock.write('221 bye\r\n'); sock.end(); }
      }
    });
  });
  const port = await new Promise((r) => smtp.listen(0, '127.0.0.1', () => r(smtp.address().port)));
  try {
    const mailer = createMailer({ dataDir: '/nonexistent', mail: { mode: 'smtp', host: '127.0.0.1', port, secure: false, startTls: false, user: 'u', pass: 'p', from: 'breakAPI <no-reply@example.com>' } }, { log: quiet });
    await mailer.send({ to: 'olu@example.com', subject: 'Confirm\r\nBcc: injected@example.com', text: 'line one\n.starts with a dot\n' });
    assert.ok(seen.some((l) => l.startsWith('AUTH PLAIN ')));
    assert.ok(seen.includes('MAIL FROM:<no-reply@example.com>'));
    assert.ok(seen.includes('RCPT TO:<olu@example.com>'));
    assert.match(data, /^Subject: Confirm Bcc: injected@example\.com$/m, 'header injection is neutralized');
    assert.ok(!/^Bcc:/m.test(data));
    assert.match(data, /\r\n\.\.starts with a dot/);
  } finally {
    smtp.close();
  }
});

test('owners can always delete their own project, verified or not; members can only leave', async () => {
  const open = await startApp();
  try {
    const root = open.client();
    await root.call('POST', '/api/auth/setup', { setupToken: open.app.setupToken(), name: 'Root', email: 'root@example.com', password: PASSWORD });
    const { body: p } = await root.call('POST', '/api/projects', { name: 'mine' });
    assert.equal((await root.call('DELETE', `/api/projects/${p.id}`)).status, 200);
    assert.equal((await root.call('GET', '/api/projects')).body.length, 0);

    // A user whose email is not verified yet can still delete what they own (and sees a clear error otherwise).
    const c = open.client();
    const { body: issued } = await root.call('POST', '/api/admin/users', { email: 'sid@example.com', name: 'Sid', password: PASSWORD });
    await c.call('POST', '/api/auth/login', { email: 'sid@example.com', password: PASSWORD, setupToken: issued.credentials.setupToken });
    const { body: q } = await c.call('POST', '/api/projects', { name: 'sid project' });
    // simulate the verification being lost: delete must still work
    const sid = Object.values(open.app.store.data.users).find((u) => u.email === 'sid@example.com');
    sid.emailVerifiedAt = null;
    assert.equal((await c.call('DELETE', `/api/projects/${q.id}`)).status, 200);

    // Deleting a project also removes its scans and stops any running one.
    const { body: r } = await root.call('POST', '/api/projects', { name: 'with scans' });
    open.app.store.data.scans.scan_fake = { id: 'scan_fake', projectId: r.id, status: 'completed', findings: [], log: [], checks: [], createdAt: new Date().toISOString() };
    assert.equal((await root.call('DELETE', `/api/projects/${r.id}`)).status, 200);
    assert.equal(open.app.store.data.scans.scan_fake, undefined);
    assert.equal((await root.call('GET', `/api/scans/scan_fake`)).status, 404);
  } finally {
    open.stop();
  }
});

test('projects nobody owns (from before accounts) can be claimed or deleted by an admin', async () => {
  const e = await startApp();
  try {
    // Seed legacy projects as startup migration leaves them: no members.
    const now = new Date().toISOString();
    for (const [id, name] of [['prj_legacy1', 'Legacy one'], ['prj_legacy2', 'Legacy two']]) {
      e.app.store.data.projects[id] = { id, name, createdAt: now, members: [], authorization: null, authorizationHistory: [], verifiedHosts: [], target: { baseUrl: 'http://localhost:4010', endpoints: [] }, accounts: [], controls: {}, audit: [] };
    }
    e.app.store.data.scans.scan_legacy = { id: 'scan_legacy', projectId: 'prj_legacy2', status: 'completed', findings: [], log: [], checks: [], createdAt: now };
    const admin = e.client();
    await admin.call('POST', '/api/auth/setup', { setupToken: e.app.setupToken(), name: 'Ada', email: 'ada@example.com', password: PASSWORD });
    // Setup adopts projects that exist at that moment, so add a fresh orphan afterwards, as a CLI-created admin would face.
    e.app.store.data.projects.prj_legacy3 = { ...e.app.store.data.projects.prj_legacy1, id: 'prj_legacy3', name: 'Legacy three', members: [] };
    const list = (await admin.call('GET', '/api/admin/orphans')).body;
    assert.deepEqual(list.map((o) => o.id), ['prj_legacy3']);
    assert.ok(!JSON.stringify(list).includes('authorization'), 'admins see only name, address and scan count');
    const user = e.client();
    const { body: issued } = await admin.call('POST', '/api/admin/users', { email: 'uma@example.com', name: 'Uma', password: PASSWORD });
    await user.call('POST', '/api/auth/login', { email: 'uma@example.com', password: PASSWORD, setupToken: issued.credentials.setupToken });
    assert.equal((await user.call('GET', '/api/admin/orphans')).status, 403);
    assert.equal((await user.call('POST', '/api/admin/orphans/prj_legacy3/claim')).status, 403);
    assert.equal((await user.call('GET', '/api/projects/prj_legacy3')).status, 404, 'nobody can open it meanwhile');
    assert.equal((await admin.call('POST', '/api/admin/orphans/prj_legacy3/claim')).status, 200);
    assert.equal((await admin.call('GET', '/api/admin/orphans')).body.length, 0);
    const mine = await admin.call('GET', '/api/projects/prj_legacy3');
    assert.equal(mine.body.myRole, 'owner');
    assert.equal((await admin.call('POST', '/api/admin/orphans/prj_legacy3/claim')).status, 404, 'claimed projects are no longer orphans');
    assert.equal((await admin.call('DELETE', '/api/admin/orphans/prj_legacy3')).status, 404, 'the orphan route cannot delete owned projects');
    assert.equal((await admin.call('DELETE', '/api/projects/prj_legacy3')).status, 200);
  } finally {
    e.stop();
  }
});

test('behind a reverse proxy on a public domain: origin, cookies, client IP and emailed links', async () => {
  const site = 'https://breakapi.example.com';
  const e = await startApp({ publicUrl: site, trustProxy: true });
  try {
    // What the proxy forwards: the browser's Origin, and the visitor's IP / scheme in X-Forwarded-*.
    const proxied = { origin: site, 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.9, 10.0.0.1' };
    const a = e.client();
    const setup = await a.call('POST', '/api/auth/setup', { setupToken: e.app.setupToken(), name: 'Ada', email: 'ada@example.com', password: PASSWORD }, { headers: proxied });
    assert.equal(setup.status, 200, JSON.stringify(setup.body));
    assert.match(setup.setCookie, /Secure/, 'session cookie is Secure because the public URL is https');
    assert.match(setup.setCookie, /HttpOnly/);
    assert.match(setup.headers.get('strict-transport-security') || '', /max-age/);
    const sessions = (await a.call('GET', '/api/auth/sessions', null, { headers: proxied })).body;
    assert.equal(sessions[0].ip, '203.0.113.9', 'the visitor IP comes from the first X-Forwarded-For entry');

    // The same write from any other origin is refused, even with the right cookie and header.
    assert.equal((await a.call('POST', '/api/projects', { name: 'x' }, { headers: { ...proxied, origin: 'https://evil.example' } })).status, 403);
    assert.equal((await a.call('POST', '/api/projects', { name: 'ok' }, { headers: proxied })).status, 200);

    // Links in email point at the public address, never at the backend's own host name.
    await a.call('POST', '/api/auth/forgot', { email: 'ada@example.com' }, { headers: proxied });
    assert.ok(e.outbox().join('\n').includes(`${site}/#/reset/`), 'reset link uses the public URL');
    assert.ok(!e.outbox().join('\n').includes('127.0.0.1'));
  } finally {
    e.stop();
  }
});
