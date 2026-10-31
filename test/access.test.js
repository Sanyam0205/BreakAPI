import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { loadConfig } from '../src/config.js';

const quiet = { info() {}, error() {} };
const PASSWORD = 'correct-horse-staple-42';
const DAY = 86400_000;
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

function clientFor(base) {
  let sid = '';
  const call = async (method, path, body) => {
    const headers = { 'content-type': 'application/json', 'x-breakapi': '1' };
    if (sid) headers.cookie = `bp_sid=${sid}`;
    const r = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
    const setCookie = r.headers.get('set-cookie');
    if (setCookie) sid = (setCookie.match(/bp_sid=([^;]*)/) || [])[1] || '';
    return { status: r.status, body: await r.json().catch(() => null), setCookie };
  };
  return { call };
}

let dataDir, app, base, admin;
const start = async () => {
  app = createApp({ config: loadConfig({}, { dataDir, quiet: true }), log: quiet });
  base = `http://127.0.0.1:${await listen(app.server)}`;
};
const issue = async (email, password) => (await admin.call('POST', '/api/admin/users', { email, name: email.split('@')[0], password })).body;
const adminLogin = () => admin.call('POST', '/api/auth/login', { email: 'ada@example.com', password: PASSWORD });

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'breakapi-access-'));
  await start();
  admin = clientFor(base);
  await admin.call('POST', '/api/auth/setup', { setupToken: app.setupToken(), name: 'Ada', email: 'ada@example.com', password: PASSWORD });
});
after(async () => {
  await app.shutdown();
  app.server.close();
  rmSync(dataDir, { recursive: true, force: true });
});

test('an issued account needs email, password and setup token; admins sign in without a token', async () => {
  const { credentials: c } = await issue('ivy@example.com', PASSWORD);
  assert.equal(c.email, 'ivy@example.com');
  assert.equal(c.password, PASSWORD);
  const days = (new Date(c.expiresAt) - Date.now()) / DAY;
  assert.ok(days > 29.9 && days <= 30, 'access lasts 30 days');

  const u = clientFor(base);
  const noToken = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD });
  const wrongToken = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: 'not-the-token' });
  const wrongPassword = await u.call('POST', '/api/auth/login', { email: c.email, password: 'wrong-password-value', setupToken: c.setupToken });
  const nobody = await u.call('POST', '/api/auth/login', { email: 'nobody@example.com', password: PASSWORD, setupToken: c.setupToken });
  for (const r of [noToken, wrongToken, wrongPassword, nobody]) {
    assert.equal(r.status, 401);
    assert.equal(r.body.error, nobody.body.error, 'failures look alike, so nothing reveals which part was wrong');
  }
  const ok = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: c.setupToken });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.user.accessExpiresAt, c.expiresAt);
  assert.equal((await adminLogin()).status, 200);

  const db = readFileSync(join(dataDir, 'db.json'), 'utf8') + JSON.stringify(app.store.data);
  assert.ok(!db.includes(c.setupToken) && !db.includes(PASSWORD), 'neither secret is stored in the clear');
});

test('a blank password is generated; a weak one is refused; only admins can issue', async () => {
  const { credentials: c } = await issue('gen@example.com');
  assert.ok(c.password.length >= 12);
  assert.equal((await clientFor(base).call('POST', '/api/auth/login', { email: c.email, password: c.password, setupToken: c.setupToken })).status, 200);
  assert.equal((await admin.call('POST', '/api/admin/users', { email: 'weak@example.com', password: 'short' })).status, 400);
  assert.equal((await admin.call('GET', '/api/admin/users')).body.some((u) => u.email === 'weak@example.com'), false, 'a refused request creates nothing');
  const u = clientFor(base);
  await u.call('POST', '/api/auth/login', { email: c.email, password: c.password, setupToken: c.setupToken });
  assert.equal((await u.call('POST', '/api/admin/users', { email: 'x@example.com' })).status, 403);
  assert.equal((await clientFor(base).call('POST', '/api/admin/users', { email: 'x@example.com' })).status, 401);
});

test('an issued account has one session, which lasts until its access ends and has no idle timeout', async () => {
  const { credentials: c } = await issue('solo@example.com', PASSWORD);
  const creds = { email: c.email, password: PASSWORD, setupToken: c.setupToken };
  const first = clientFor(base);
  const r = await first.call('POST', '/api/auth/login', creds);
  const maxAge = Number(r.setCookie.match(/Max-Age=(\d+)/)[1]);
  assert.ok(maxAge > 29.9 * 86400, `cookie lasts about 30 days (${maxAge}s)`);

  for (const s of Object.values(app.store.data.sessions)) {
    if (s.expiresAt) s.lastSeenAt = new Date(Date.now() - 20 * DAY).toISOString();
  }
  assert.equal((await first.call('GET', '/api/projects')).status, 200, 'idle for 20 days and still signed in');

  const second = clientFor(base);
  await second.call('POST', '/api/auth/login', creds);
  assert.equal((await first.call('GET', '/api/projects')).status, 401, 'signing in elsewhere ends the earlier session');
  assert.equal((await second.call('GET', '/api/projects')).status, 200);
});

test('after 30 days the session ends and sign-in explains why; issuing again restores access', async () => {
  const { user, credentials: c } = await issue('late@example.com', PASSWORD);
  const u = clientFor(base);
  await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: c.setupToken });
  app.store.data.users[user.id].access.expiresAt = new Date(Date.now() - 1000).toISOString();

  assert.equal((await u.call('GET', '/api/projects')).status, 401, 'the running session ends');
  const ended = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: c.setupToken });
  assert.equal(ended.status, 403);
  assert.match(ended.body.error, /30 days/);
  const wrong = await u.call('POST', '/api/auth/login', { email: c.email, password: 'wrong-password-value', setupToken: c.setupToken });
  assert.equal(wrong.status, 401, 'the reason is only shown to someone with the right details');
  assert.ok((await admin.call('GET', '/api/admin/users')).body.find((x) => x.id === user.id).accessEnded);

  const again = await admin.call('POST', `/api/admin/users/${user.id}/reissue`);
  assert.equal(again.status, 200);
  const old = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: c.setupToken });
  assert.equal(old.status, 401, 'the old password and token stop working');
  const { password, setupToken } = again.body.credentials;
  assert.equal((await u.call('POST', '/api/auth/login', { email: c.email, password, setupToken })).status, 200);
  assert.equal((await admin.call('POST', `/api/admin/users/${(await admin.call('GET', '/api/auth/me')).body.user.id}/reissue`)).status, 400, 'admins have nothing to issue');
});

test('a user made admin has no time limit, and a former admin must be issued again', async () => {
  const { user, credentials: c } = await issue('promo@example.com', PASSWORD);
  assert.equal((await admin.call('PATCH', `/api/admin/users/${user.id}`, { role: 'admin' })).status, 200);
  const u = clientFor(base);
  const asAdmin = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD });
  assert.equal(asAdmin.status, 200);
  assert.equal(asAdmin.body.user.accessExpiresAt, null);
  assert.equal((await admin.call('PATCH', `/api/admin/users/${user.id}`, { role: 'user' })).status, 200);
  assert.equal((await u.call('GET', '/api/projects')).status, 401);
  const blocked = await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD });
  assert.equal(blocked.status, 403);
  assert.match(blocked.body.error, /no active access/);
});

test('every page carries the disclaimer, and the public files exist', async () => {
  const html = await (await fetch(`${base}/`)).text();
  assert.match(html, /<footer class="disclaimer"[^>]*>This is a testing demo application only\.<\/footer>/);
  const doc = await fetch(`${base}/EXAMPLES.md`);
  assert.equal(doc.status, 200);
});

// Keep this last: it restarts the app.
test('access ends when the app restarts, but admins and accounts remain', async () => {
  const { user, credentials: c } = await issue('run@example.com', PASSWORD);
  const u = clientFor(base);
  await u.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: c.setupToken });
  assert.equal((await u.call('GET', '/api/projects')).status, 200);
  await app.shutdown();
  await new Promise((resolve) => { app.server.close(resolve); app.server.closeAllConnections(); });

  await start();
  const after = clientFor(base);
  const blocked = await after.call('POST', '/api/auth/login', { email: c.email, password: PASSWORD, setupToken: c.setupToken });
  assert.equal(blocked.status, 403);
  assert.match(blocked.body.error, /restarted/);

  admin = clientFor(base);
  assert.equal((await adminLogin()).status, 200, 'the admin account outlives a restart');
  const again = await admin.call('POST', `/api/admin/users/${user.id}/reissue`);
  const { password, setupToken } = again.body.credentials;
  assert.equal((await after.call('POST', '/api/auth/login', { email: c.email, password, setupToken })).status, 200);
});
