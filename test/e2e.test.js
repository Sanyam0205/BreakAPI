import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { createDemoServer, demoTokens, stats } from '../demo/vulnerable-api.js';
import { sleep } from '../src/util.js';
import { blockedAddress } from '../src/verify.js';

let app, demo, base, demoHost, dataDir;
let TOKEN = ''; // session id of the signed-in admin, set in before()

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

async function api(method, path, body, { auth = true, csrf = true } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (auth) headers.cookie = `bp_sid=${TOKEN}`;
  if (csrf) headers['x-breakapi'] = '1';
  const r = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json() };
}

const inDays = (d) => new Date(Date.now() + d * 86400_000).toISOString();

function authorization(overrides = {}) {
  return {
    authorizerName: 'Test Owner',
    authorizerEmail: 'owner@example.com',
    authorizerRole: 'Engineering lead',
    relationship: 'owner',
    allowedHosts: [demoHost],
    allowedTests: ['config', 'exposure', 'authn', 'authz', 'input', 'validation', 'identity', 'logic', 'ratelimit'],
    allowWriteMethods: false,
    expiresAt: inDays(7),
    attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true },
    undertaking: { accepted: true, typedName: 'Test Owner' },
    ...overrides,
  };
}

async function setupProject(name, authOverrides) {
  const { body: p } = await api('POST', '/api/projects', { name });
  await api('PUT', `/api/projects/${p.id}/authorization`, authorization(authOverrides));
  await api('POST', `/api/projects/${p.id}/import`, { format: 'openapi', content: readFileSync(new URL('../demo/openapi.json', import.meta.url), 'utf8') });
  await api('PUT', `/api/projects/${p.id}/target`, { baseUrl: `http://${demoHost}` });
  const t = demoTokens();
  await api('POST', `/api/projects/${p.id}/accounts`, { label: 'alice', role: 'user', authType: 'bearer', secret: t.alice, resourceIds: { id: '1', email: 'alice@demo.test' } });
  await api('POST', `/api/projects/${p.id}/accounts`, { label: 'bob', role: 'user', authType: 'bearer', secret: t.bob, resourceIds: { id: '2', email: 'bob@demo.test' } });
  await api('PUT', `/api/projects/${p.id}/controls`, { maxRequests: 1000, rps: 50, burstRps: 100, rateLimitBurst: 20, timeoutMs: 5000, stopOnErrorStreak: 10 });
  return p.id;
}

async function waitForScan(id) {
  for (let i = 0; i < 300; i++) {
    const { body } = await api('GET', `/api/scans/${id}`);
    if (!['queued', 'running', 'paused'].includes(body.status)) return body;
    await sleep(100);
  }
  throw new Error('scan did not finish');
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'breakapi-test-'));
  demo = createDemoServer();
  demoHost = `localhost:${await listen(demo)}`;
  app = createApp({ config: loadConfig({}, { dataDir, quiet: true }), log: { info() {}, error: console.error } });
  base = `http://127.0.0.1:${await listen(app.server)}`;
  // First-run setup creates the admin; the admin is also the authorizer in these tests (self-authorized).
  const r = await fetch(`${base}/api/auth/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-breakapi': '1' },
    body: JSON.stringify({ setupToken: app.setupToken(), name: 'Test Owner', email: 'owner@example.com', password: 'a-long-test-passphrase' }),
  });
  assert.equal(r.status, 200);
  TOKEN = r.headers.get('set-cookie').match(/bp_sid=([^;]+)/)[1];
});

after(() => {
  app.server.close();
  demo.close();
  rmSync(dataDir, { recursive: true, force: true });
});

test('API requires a session and the CSRF header', async () => {
  assert.equal((await api('GET', '/api/projects', null, { auth: false })).status, 401);
  assert.equal((await api('POST', '/api/projects', { name: 'x' }, { csrf: false })).status, 403);
  assert.equal((await api('POST', '/api/auth/login', { email: 'owner@example.com', password: 'wrong-password-123' }, { auth: false })).status, 401);
});

test('authorization is validated before it is recorded', async () => {
  const { body: p } = await api('POST', '/api/projects', { name: 'validation' });
  const missingAttestation = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ attestations: { ownsOrAuthorized: true } }));
  assert.equal(missingAttestation.status, 400);
  const wildcard = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ allowedHosts: ['*.example.com'] }));
  assert.equal(wildcard.status, 400);
  const tooLong = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ expiresAt: inDays(365) }));
  assert.equal(tooLong.status, 400);
  const delegatedNoNote = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ relationship: 'delegated' }));
  assert.equal(delegatedNoNote.status, 400);
});

test('the legal undertaking must be accepted by typing the authorizer\'s name', async () => {
  const { body: p } = await api('POST', '/api/projects', { name: 'undertaking' });
  const missing = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ undertaking: undefined }));
  assert.equal(missing.status, 400);
  assert.match(missing.body.error, /undertaking/i);
  const notAccepted = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ undertaking: { accepted: false, typedName: 'Test Owner' } }));
  assert.equal(notAccepted.status, 400);
  const wrongName = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ undertaking: { accepted: true, typedName: 'Someone Else' } }));
  assert.equal(wrongName.status, 400);
  assert.match(wrongName.body.error, /full name/i);
  const ok = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ undertaking: { accepted: true, typedName: '  test   OWNER ' } }));
  assert.equal(ok.status, 200);
  const u = ok.body.authorization.undertaking;
  assert.ok(u.version && u.sha256 && u.acceptedAt);
  assert.match(ok.body.authorization.verificationToken, /^breakapi-verify-/);
  assert.ok(ok.body.audit.some((e) => e.event === 'undertaking.accepted'));
  const meta = await api('GET', '/api/meta');
  assert.equal(meta.body.undertaking.sha256, u.sha256);
  assert.ok(meta.body.authLimitations.length > 3);
});

test('every non-local host in scope must be verified, and the challenge is checked per host', async () => {
  let token = '';
  const verifiable = createDemoServer({ verifyToken: () => token });
  const port = await listen(verifiable);
  const host = `0.0.0.0:${port}`; // not loopback, but reachable: it can pass the challenge
  try {
    const { body: p } = await api('POST', '/api/projects', { name: 'verify' });
    const rec = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ allowedHosts: [host, 'blocked.invalid'], allowedTests: ['config'] }));
    await api('POST', `/api/projects/${p.id}/import`, { format: 'manual', content: 'GET /api/health public' });
    await api('PUT', `/api/projects/${p.id}/target`, { baseUrl: `http://${host}` });
    assert.equal(rec.status, 200);
    const startBlocked = await api('POST', `/api/projects/${p.id}/scans`, {});
    assert.equal(startBlocked.status, 422);
    assert.match(startBlocked.body.error, /not verified/);

    token = 'wrong-token';
    assert.equal((await api('POST', `/api/projects/${p.id}/verify`, { host })).status, 400);
    token = rec.body.authorization.verificationToken;
    const verified = await api('POST', `/api/projects/${p.id}/verify`, { host });
    assert.equal(verified.status, 200, JSON.stringify(verified.body));
    assert.equal(verified.body.hostStatus.find((h) => h.host === host).verified, true);

    // The second host is still unverified, so the scan stays blocked.
    const stillBlocked = await api('POST', `/api/projects/${p.id}/scans`, {});
    assert.equal(stillBlocked.status, 422);
    assert.match(stillBlocked.body.error, /blocked\.invalid/);
    assert.equal((await api('POST', `/api/projects/${p.id}/verify`, { host: 'blocked.invalid' })).status, 400);
    assert.equal((await api('POST', `/api/projects/${p.id}/verify`, { host: 'not-in-scope.example' })).status, 400);

    // Drop the unreachable host: re-record the authorization (new token) and verify again.
    const again = await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ allowedHosts: [host], allowedTests: ['config'] }));
    assert.notEqual(again.body.authorization.verificationToken, rec.body.authorization.verificationToken);
    assert.equal(again.body.hostStatus[0].verified, false, 'verification belongs to the previous authorization');
    token = again.body.authorization.verificationToken;
    await api('POST', `/api/projects/${p.id}/verify`, { host });
    const start = await api('POST', `/api/projects/${p.id}/scans`, {});
    assert.equal(start.status, 200, JSON.stringify(start.body));
    const scan = await waitForScan(start.body.id);
    assert.equal(scan.status, 'completed', scan.stopReason || scan.error);
    assert.equal(scan.verificationSnapshot[0].verified, true);

    // The challenge is re-run at the start of every scan and fails closed.
    token = 'revoked';
    const failClosed = await api('POST', `/api/projects/${p.id}/scans`, {});
    assert.equal(failClosed.status, 422);
    assert.match(failClosed.body.error, /re-verification/);
  } finally {
    verifiable.close();
  }
});

test('cloud-metadata and link-local targets are never contacted for verification', async () => {
  assert.equal(blockedAddress('169.254.169.254'), true);
  assert.equal(blockedAddress('fe80::1'), true);
  assert.equal(blockedAddress('::ffff:169.254.169.254'), true);
  assert.equal(blockedAddress('10.0.0.5'), false);
  const { body: p } = await api('POST', '/api/projects', { name: 'metadata' });
  await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ allowedHosts: ['169.254.169.254'] }));
  const r = await api('POST', `/api/projects/${p.id}/verify`, { host: '169.254.169.254' });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /link-local|metadata/);
  const local = await api('POST', `/api/projects/${p.id}/verify`, { host: 'localhost:4010' });
  assert.equal(local.status, 400);
});

test('scans are blocked when the target is out of scope or unverified', async () => {
  const id = await setupProject('out of scope', { allowedHosts: ['other.localhost:1'] });
  const res = await api('POST', `/api/projects/${id}/scans`, {});
  assert.equal(res.status, 422);
  assert.match(res.body.error, /not in the authorized scope/);

  await api('PUT', `/api/projects/${id}/authorization`, authorization({ allowedHosts: ['api.example.com'] }));
  await api('PUT', `/api/projects/${id}/target`, { baseUrl: 'https://api.example.com' });
  const unverified = await api('POST', `/api/projects/${id}/scans`, {});
  assert.equal(unverified.status, 422);
  assert.match(unverified.body.error, /not verified/);
});

test('full scan finds the demo API weaknesses without sending DELETE or writes', async () => {
  const id = await setupProject('demo');
  const deletesBefore = stats.deletes;
  const writesBefore = stats.writes;
  const start = await api('POST', `/api/projects/${id}/scans`, {});
  assert.equal(start.status, 200, JSON.stringify(start.body));
  const scan = await waitForScan(start.body.id);
  assert.equal(scan.status, 'completed', scan.stopReason || scan.error);

  const titles = scan.findings.map((f) => `${f.severity} ${f.title} @ ${f.endpoint}`);
  const has = (re) => assert.ok(titles.some((t) => re.test(t)), `expected ${re} in:\n${titles.join('\n')}`);
  has(/high Cross-account data access .* GET \/api\/users\/\{id\}$/);
  has(/high Endpoint accessible without authentication @ GET \/api\/invoices\/\{id\}/);
  has(/high Admin function accessible .* GET \/api\/admin\/users/);
  has(/critical JWT with alg "none" is accepted/);
  has(/critical JWT is signed with a guessable secret/);
  has(/high CORS reflects any origin and allows credentials/);
  has(/high Possible SQL injection .* GET \/api\/search/);
  has(/medium Input reflected into HTML .* GET \/api\/greet/);
  has(/high Environment file publicly accessible/);
  has(/medium Stack trace exposed/);
  has(/medium No rate limiting observed/);
  has(/low Server technology and version disclosed/);

  // The properly protected orders endpoint must not be flagged.
  assert.ok(!titles.some((t) => /\/orders/.test(t)), 'orders endpoint should not be flagged');
  assert.equal(stats.deletes, deletesBefore, 'DELETE must never be sent');
  assert.equal(stats.writes, writesBefore, 'writes must not be sent without authorization');

  // Secrets never appear in stored evidence or logs.
  const stored = readFileSync(join(dataDir, 'db.json'), 'utf8');
  assert.ok(!stored.includes(demoTokens().alice.split('.')[2]), 'raw token must not be stored');
});

test('request budget halts the scan', async () => {
  const id = await setupProject('budget');
  await api('PUT', `/api/projects/${id}/controls`, { maxRequests: 10, rps: 50 });
  const { body } = await api('POST', `/api/projects/${id}/scans`, {});
  const scan = await waitForScan(body.id);
  assert.equal(scan.status, 'halted');
  assert.match(scan.stopReason, /budget/);
  assert.equal(scan.requestsSent, 10);
});

test('stop control ends a running scan, and rerun compares results', async () => {
  const id = await setupProject('stop');
  await api('PUT', `/api/projects/${id}/controls`, { maxRequests: 1000, rps: 5 });
  const { body } = await api('POST', `/api/projects/${id}/scans`, {});
  await sleep(300);
  assert.equal((await api('POST', `/api/scans/${body.id}/stop`)).status, 200);
  const stopped = await waitForScan(body.id);
  assert.equal(stopped.status, 'stopped');

  await api('PUT', `/api/projects/${id}/controls`, { maxRequests: 1000, rps: 50, burstRps: 100, rateLimitBurst: 10 });
  const rerun = await api('POST', `/api/scans/${body.id}/rerun`);
  const done = await waitForScan(rerun.body.id);
  assert.equal(done.status, 'completed');
  assert.equal(done.comparison.previousScanId, body.id);
  assert.ok(done.comparison.new.length > 0);
});

test('revoking authorization purges credentials and blocks scans', async () => {
  const id = await setupProject('revoke');
  const { body } = await api('POST', `/api/projects/${id}/authorization/revoke`);
  assert.ok(body.accounts.every((a) => !a.hasSecret));
  assert.ok(body.problems.some((p) => /revoked/.test(p)));
  assert.equal((await api('POST', `/api/projects/${id}/scans`, {})).status, 422);
});

test('report page renders and escapes content', async () => {
  const { body: p } = await api('POST', '/api/projects', { name: '<script>alert(1)</script>' });
  await api('PUT', `/api/projects/${p.id}/authorization`, authorization());
  await api('POST', `/api/projects/${p.id}/import`, { format: 'manual', content: 'GET /api/health public' });
  await api('PUT', `/api/projects/${p.id}/target`, { baseUrl: `http://${demoHost}` });
  await api('PUT', `/api/projects/${p.id}/controls`, { rps: 50, burstRps: 100, rateLimitBurst: 5 });
  const { body } = await api('POST', `/api/projects/${p.id}/scans`, {});
  await waitForScan(body.id);
  const r = await fetch(`${base}/reports/${body.id}`, { headers: { cookie: `bp_sid=${TOKEN}` } });
  const html = await r.text();
  assert.equal(r.status, 200);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('<h2>AUTHORIZATION</h2>'));
});

async function optInAll(projectId) {
  const { body: p } = await api('GET', `/api/projects/${projectId}`);
  for (const e of p.target.endpoints.filter((x) => ['signup', 'login', 'order'].includes(x.kind))) {
    await api('PATCH', `/api/projects/${projectId}/endpoints/${e.id}`, { syntheticWrites: true });
  }
}

test('write requests need the global switch AND a per-endpoint opt-in; a spec import never grants it', async () => {
  const id = await setupProject('writes gate', { allowWriteMethods: true });
  const { body: before } = await api('GET', `/api/projects/${id}`);
  assert.ok(before.target.endpoints.every((e) => e.syntheticWrites === false));
  const counts = { ...stats };
  const start = await api('POST', `/api/projects/${id}/scans`, {});
  const scan = await waitForScan(start.body.id);
  assert.equal(scan.status, 'completed', scan.stopReason || scan.error);
  assert.equal(stats.signups, counts.signups, 'no signup without an opt-in');
  assert.equal(stats.orders, counts.orders, 'no order without an opt-in');
  assert.equal(stats.logins, counts.logins, 'no login attempt without an opt-in');
  assert.equal(stats.deletes, counts.deletes);
  assert.ok(!scan.findings.some((f) => ['validation', 'identity', 'logic'].includes(f.check)));
  assert.ok(scan.log.some((l) => l.note && /skipped/i.test(l.note)));

  // Opt in on the endpoints, but WITHOUT the global write switch: still nothing is sent.
  const readOnly = await setupProject('writes gate read-only');
  await optInAll(readOnly);
  const s2 = await waitForScan((await api('POST', `/api/projects/${readOnly}/scans`, {})).body.id);
  assert.equal(stats.signups, counts.signups);
  assert.ok(!s2.findings.some((f) => ['validation', 'identity', 'logic'].includes(f.check)));
});

test('synthetic checks find validation, identity and business-logic weaknesses', async () => {
  const id = await setupProject('synthetic', { allowWriteMethods: true });
  await optInAll(id);
  const counts = { ...stats };
  const scan = await waitForScan((await api('POST', `/api/projects/${id}/scans`, {})).body.id);
  assert.equal(scan.status, 'completed', scan.stopReason || scan.error);
  const titles = scan.findings.map((f) => `${f.severity} ${f.title} @ ${f.endpoint}`);
  const has = (re) => assert.ok(titles.some((t) => re.test(t)), `expected ${re} in:\n${titles.join('\n')}`);
  has(/medium Malformed email address accepted @ POST \/api\/users/);
  has(/high Privileged fields can be set by the client .* POST \/api\/users/);
  has(/high New account has full access before its email is verified/);
  has(/medium Email addresses are not normalized/);
  has(/medium A trivially weak password is accepted/);
  has(/medium Login responses reveal whether an account exists @ POST \/api\/login/);
  has(/low Text accepted for numeric field "age"/);
  has(/low Implausible value accepted for "age"/);
  has(/high Negative "quantity" accepted @ POST \/api\/orders/);
  has(/high The client decides the "price"/);
  has(/low Identical requests create duplicate records/);
  has(/low Malformed email address in data @ GET \/api\/profile-data/);
  has(/low updatedAt is earlier than createdAt/);
  has(/low Cookie "sid" is missing HttpOnly/);
  assert.ok(stats.signups > counts.signups && stats.orders > counts.orders && stats.logins > counts.logins);
  assert.equal(stats.deletes, counts.deletes, 'DELETE must never be sent');

  // Synthetic data only: markers and reserved .invalid addresses, never real-looking identities.
  const synthetic = scan.findings.flatMap((f) => f.evidence || []).map((e) => e.requestBody).filter(Boolean).join('\n');
  assert.match(synthetic, /breakapi-/);
  assert.match(synthetic, /@example\.invalid/);
  assert.ok(!/@gmail|@yahoo|@outlook/.test(synthetic));
  // The report carries the request body, the undertaking and the authorization limits.
  const report = await (await fetch(`${base}/reports/${scan.id}`, { headers: { cookie: `bp_sid=${TOKEN}` } })).text();
  assert.match(report, /<h2>UNDERTAKING<\/h2>/);
  assert.match(report, /<h2>VERIFICATION<\/h2>/);
  assert.match(report, /<h2>AUTH LIMITATIONS<\/h2>/);
  assert.match(report, /Local development only/);
  assert.match(report, /not legal advice/i);
});

test('an API that validates and recomputes server-side gets no synthetic findings', async () => {
  const fixed = createDemoServer({ fixed: true });
  const port = await listen(fixed);
  try {
    const { body: p } = await api('POST', '/api/projects', { name: 'fixed demo' });
    const host = `localhost:${port}`;
    await api('PUT', `/api/projects/${p.id}/authorization`, authorization({ allowedHosts: [host], allowWriteMethods: true }));
    await api('POST', `/api/projects/${p.id}/import`, { format: 'openapi', content: readFileSync(new URL('../demo/openapi.json', import.meta.url), 'utf8') });
    await api('PUT', `/api/projects/${p.id}/target`, { baseUrl: `http://${host}` });
    const t = demoTokens();
    await api('POST', `/api/projects/${p.id}/accounts`, { label: 'alice', role: 'user', authType: 'bearer', secret: t.alice, resourceIds: { id: '1', email: 'alice@demo.test' } });
    await api('POST', `/api/projects/${p.id}/accounts`, { label: 'bob', role: 'user', authType: 'bearer', secret: t.bob, resourceIds: { id: '2', email: 'bob@demo.test' } });
    await api('PUT', `/api/projects/${p.id}/controls`, { maxRequests: 1000, rps: 50, burstRps: 100, rateLimitBurst: 10 });
    await optInAll(p.id);
    const scan = await waitForScan((await api('POST', `/api/projects/${p.id}/scans`, {})).body.id);
    assert.equal(scan.status, 'completed', scan.stopReason || scan.error);
    assert.ok(scan.writesSent >= 10, `synthetic checks ran (${scan.writesSent} writes)`);
    const noisy = scan.findings.filter((f) => ['validation', 'identity', 'logic'].includes(f.check) || /^dataquality|^passive\|cookie/.test(f.key));
    assert.deepEqual(noisy.map((f) => f.title), []);
  } finally {
    fixed.close();
  }
});

test('write budget and scan duration are enforced by the client', async () => {
  const id = await setupProject('write budget', { allowWriteMethods: true });
  await optInAll(id);
  await api('PUT', `/api/projects/${id}/controls`, { maxRequests: 1000, rps: 50, burstRps: 100, rateLimitBurst: 10, maxWrites: 3 });
  const scan = await waitForScan((await api('POST', `/api/projects/${id}/scans`, {})).body.id);
  assert.equal(scan.status, 'completed', scan.stopReason || scan.error);
  assert.ok(scan.writesSent <= 3, `sent ${scan.writesSent} writes`);
  assert.ok(scan.log.some((l) => l.note && /write budget of 3 reached/.test(l.note)));

  await api('PUT', `/api/projects/${id}/controls`, { maxRequests: 1000, rps: 2, burstRps: 100, rateLimitBurst: 10, maxDurationMs: 60000 });
  // Stored controls cannot exceed the hard ceilings even if edited behind the API's back.
  app.store.data.projects[id].controls.maxDurationMs = 3;
  const timed = await waitForScan((await api('POST', `/api/projects/${id}/scans`, {})).body.id);
  assert.equal(timed.status, 'halted');
  assert.match(timed.stopReason, /Maximum scan duration/);
});
