import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { EXAMPLES } from '../src/lab.js';
import { sleep } from '../src/util.js';

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const quiet = { info() {}, error() {} };

// The same network rules as a public deployment: local and private targets are refused for everyone else.
async function startApp(overrides = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'breakapi-lab-'));
  const app = createApp({ config: loadConfig({}, { dataDir, quiet: true, allowLocalTargets: false, allowPrivateTargets: false, ...overrides }), log: quiet });
  return { app, dataDir, base: `http://127.0.0.1:${await listen(app.server)}` };
}

const call = async (base, method, path, body, extra = {}) => {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-breakapi': '1', ...extra }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json().catch(() => null) };
};

async function finished(app, id) {
  for (let i = 0; i < 600; i++) {
    const v = app.lab.view(id);
    if (v.status === 'finished') return v;
    await sleep(50);
  }
  throw new Error('run did not finish');
}
const runExample = async (app, exampleId) => finished(app, app.lab.start(exampleId).id);
const titles = (phase) => phase.scan.findings.map((f) => f.title);

let env;
before(async () => { env = await startApp(); });
after(() => {
  env.app.server.close();
  rmSync(env.dataDir, { recursive: true, force: true });
});

test('every example is described, and the public view hides its configuration', async () => {
  const { status, body } = await call(env.base, 'GET', '/api/lab');
  assert.equal(status, 200);
  assert.equal(body.examples.length, EXAMPLES.length);
  assert.ok(body.examples.length >= 14);
  for (const x of body.examples) {
    for (const field of ['id', 'title', 'summary', 'what', 'how', 'expect']) assert.ok(x[field], `${x.id}.${field}`);
    assert.equal(x.controls, undefined);
  }
  const doc = readFileSync(new URL('../EXAMPLES.md', import.meta.url), 'utf8');
  for (const x of EXAMPLES) assert.ok(doc.includes(`\`${x.id}\``), `EXAMPLES.md documents ${x.id}`);
});

const expected = {
  config: ['CORS reflects any origin and allows credentials'],
  exposure: ['Environment file publicly accessible'],
  authn: ['JWT with alg "none" is accepted', 'Endpoint accessible without authentication'],
  authz: ['Cross-account data access (BOLA/IDOR)', 'Admin function accessible to a non-admin account'],
  input: ['Possible SQL injection (database error on quote)', 'Input reflected into HTML without encoding (XSS risk)'],
  validation: ['Privileged fields can be set by the client (mass assignment)', 'Malformed email address accepted'],
  identity: ['New account has full access before its email is verified', 'Login responses reveal whether an account exists'],
  logic: ['The client decides the "price"', 'Negative "quantity" accepted', 'Identical requests create duplicate records'],
};

for (const [id, wanted] of Object.entries(expected)) {
  test(`example ${id} finds what its description promises`, async () => {
    const v = await runExample(env.app, id);
    const [p] = v.phases;
    assert.equal(p.scan.status, 'completed', JSON.stringify(p.scan.stopReason));
    for (const title of wanted) assert.ok(titles(p).includes(title), `${id}: ${title}\nfound: ${titles(p).join(' | ')}`);
    assert.equal(p.seen.deletes, 0);
    assert.equal(p.seen.requests, p.scan.requestsSent, 'the target counted what the scanner says it sent');
  });
}

test('rate-limit example: a limit added between phases shows as fixed', async () => {
  const v = await runExample(env.app, 'ratelimit');
  assert.ok(titles(v.phases[0]).includes('No rate limiting observed'));
  assert.deepEqual(titles(v.phases[1]), []);
  assert.equal(v.phases[1].scan.comparison.fixed.length, 1);
});

test('retest example: the patched API shows fixed and still-open findings', async () => {
  const v = await runExample(env.app, 'retest');
  const cmp = v.phases[1].scan.comparison;
  assert.ok(cmp.fixed.some((f) => f.title === 'Admin function accessible to a non-admin account'));
  assert.ok(cmp.stillOpen.some((f) => f.title === 'Environment file publicly accessible'));
  assert.equal(cmp.new.length, 0);
});

test('full example runs every check and writes only with its opt-ins', async () => {
  const [p] = (await runExample(env.app, 'full')).phases;
  assert.equal(p.scan.status, 'completed');
  assert.ok(p.scan.findings.length > 30, `found ${p.scan.findings.length}`);
  assert.ok(p.seen.writes > 0);
  assert.equal(p.seen.deletes, 0);
  assert.ok(p.scan.checks.filter((c) => c.status === 'done').length >= 9);
});

test('consent example: no authorization, expired or out of scope sends nothing', async () => {
  const v = await runExample(env.app, 'consent');
  assert.equal(v.phases.length, 3);
  for (const p of v.phases) {
    assert.equal(p.scan.status, 'blocked');
    assert.ok(p.scan.problems.length > 0);
    assert.equal(p.seen.requests, 0);
  }
  assert.match(v.phases[1].scan.problems.join(' '), /expired/i);
  assert.match(v.phases[2].scan.problems.join(' '), /not in the authorized scope/);
});

test('budget example halts at exactly the budget', async () => {
  const [p] = (await runExample(env.app, 'budget')).phases;
  assert.equal(p.scan.status, 'halted');
  assert.equal(p.scan.requestsSent, 12);
  assert.equal(p.seen.requests, 12);
  assert.ok(p.scan.checks.some((c) => c.status === 'incomplete'));
});

test('write example: the target gets no writes until both permissions are on', async () => {
  const [off, onlySwitch, both] = (await runExample(env.app, 'writes')).phases;
  assert.equal(off.seen.writes, 0);
  assert.equal(onlySwitch.seen.writes, 0);
  assert.ok(both.seen.writes > 0);
  for (const p of [off, onlySwitch, both]) assert.equal(p.seen.deletes, 0);
});

test('lab requests cannot be aimed elsewhere, and need no account', async () => {
  const http = await import('node:http');
  let hits = 0;
  const other = http.createServer((req, res) => {
    hits++;
    res.end('{}');
  });
  const port = await listen(other);
  try {
    const url = `http://127.0.0.1:${port}`;
    const start = await call(env.base, 'POST', '/api/lab/runs', { exampleId: 'config', baseUrl: url, target: { baseUrl: url }, allowedHosts: [`127.0.0.1:${port}`], host: `127.0.0.1:${port}`, lab: true });
    assert.equal(start.status, 200);
    const v = await finished(env.app, start.body.id);
    assert.equal(v.phases[0].scan.status, 'completed');
    assert.equal(hits, 0, 'nothing reached the address in the request');
    assert.ok(!JSON.stringify(v).includes(`:${port}/`));
    assert.equal((await call(env.base, 'POST', '/api/lab/runs', { exampleId: `http://127.0.0.1:${port}` })).status, 404);
    assert.equal((await call(env.base, 'POST', '/api/lab/runs', { exampleId: '__proto__' })).status, 404);
  } finally {
    other.close();
  }
});

test('the lab exception does not reach real projects: localhost is still refused for them', async () => {
  const admin = await call(env.base, 'POST', '/api/auth/setup', { setupToken: env.app.setupToken(), name: 'Ada', email: 'ada@example.com', password: 'correct-horse-staple-42' });
  assert.equal(admin.status, 200);
  const cookie = (await fetch(`${env.base}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-breakapi': '1' },
    body: JSON.stringify({ email: 'ada@example.com', password: 'correct-horse-staple-42' }),
  })).headers.get('set-cookie').split(';')[0];
  const { body: p } = await call(env.base, 'POST', '/api/projects', { name: 'real', lab: true }, { cookie });
  assert.notEqual(p.lab, true, 'a request cannot mark a project as a lab project');
  const rec = await call(env.base, 'PUT', `/api/projects/${p.id}/authorization`, {
    authorizerName: 'Ada', authorizerEmail: 'ada@example.com', relationship: 'owner', allowedHosts: ['localhost:4010'], allowedTests: ['config'], lab: true,
    expiresAt: new Date(Date.now() + 86400_000).toISOString(), attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true }, undertaking: { accepted: true, typedName: 'Ada' },
  }, { cookie });
  assert.ok(rec.body.problems?.some((x) => /cannot be tested from this server/.test(x)) || rec.status === 400, JSON.stringify(rec.body));
});

test('lab runs stay out of real data, and reports carry the disclaimer and a demo notice', async () => {
  const v = await runExample(env.app, 'config');
  env.app.store.saveNow();
  const db = readFileSync(join(env.dataDir, 'db.json'), 'utf8');
  assert.ok(!db.includes(v.phases[0].scan.id));
  assert.equal(Object.values(env.app.store.data.projects).filter((p) => p.lab).length, 0);
  const report = await fetch(`${env.base}/reports/lab/${v.id}/0`);
  assert.equal(report.status, 200);
  const html = await report.text();
  assert.match(html, /This is a testing demo application only\./);
  assert.match(html, /no real system was contacted/);
  assert.equal((await fetch(`${env.base}/reports/lab/nope/0`)).status, 404);
  assert.equal((await call(env.base, 'GET', '/api/lab/runs/nope')).status, 404);
});

test('runs need the CSRF header, can be stopped, and are capped per server and per visitor', async () => {
  const e = await startApp();
  try {
    const bare = await fetch(`${e.base}/api/lab/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"exampleId":"config"}' });
    assert.equal(bare.status, 403);
    const a = await call(e.base, 'POST', '/api/lab/runs', { exampleId: 'full' });
    const b = await call(e.base, 'POST', '/api/lab/runs', { exampleId: 'full' });
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    const busy = await call(e.base, 'POST', '/api/lab/runs', { exampleId: 'full' });
    assert.equal(busy.status, 429);
    assert.equal((await call(e.base, 'POST', `/api/lab/runs/${a.body.id}/stop`)).status, 200);
    assert.equal((await call(e.base, 'POST', `/api/lab/runs/${b.body.id}/stop`)).status, 200);
    const stopped = await finished(e.app, a.body.id);
    await finished(e.app, b.body.id);
    assert.equal(stopped.stopRequested, true);
    assert.ok(stopped.phases[0].scan.requestsSent < 108, 'it ended early');
    let last;
    for (let i = 0; i < 20; i++) {
      last = await call(e.base, 'POST', '/api/lab/runs', { exampleId: 'consent' });
      if (last.status === 429 && /Too many/.test(last.body.error)) break;
      if (last.status === 200) await finished(e.app, last.body.id);
    }
    assert.equal(last.status, 429);
    assert.match(last.body.error, /Too many/);
  } finally {
    e.app.server.close();
    rmSync(e.dataDir, { recursive: true, force: true });
  }
});

test('the lab can be turned off', async () => {
  const e = await startApp({ lab: false });
  try {
    assert.equal((await call(e.base, 'GET', '/api/lab')).status, 404);
    assert.equal((await call(e.base, 'POST', '/api/lab/runs', { exampleId: 'config' })).status, 404);
    assert.equal((await call(e.base, 'GET', '/api/auth/me')).body.lab, false);
  } finally {
    e.app.server.close();
    rmSync(e.dataDir, { recursive: true, force: true });
  }
});
