// Contract tests between breakAPI and the simulation backend (the separate breakapi-sim repo).
// They run when the sim is checked out next to this repo (../breakAPI-sim) or at BREAKAPI_SIM_DIR,
// and are skipped otherwise. CI checks the sim out, so they always run there.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createApp } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { isSimEntry } from '../src/scope.js';
import { sleep } from '../src/util.js';

const here = dirname(fileURLToPath(import.meta.url));
const simDir = resolve(process.env.BREAKAPI_SIM_DIR || join(here, '..', '..', 'breakAPI-sim'));
const simEntry = join(simDir, 'src', 'server.js');
const skip = existsSync(simEntry) ? false : `breakapi-sim not found at ${simDir} (set BREAKAPI_SIM_DIR)`;
// CI sets this, so a missing checkout fails the build instead of silently skipping the contract.
if (skip && process.env.BREAKAPI_REQUIRE_SIM) throw new Error(skip);

const KEY = 'contract-test-control-key-0123456789';
const quiet = { info() {}, error() {} };
const listen = (server) => new Promise((ok) => server.listen(0, '127.0.0.1', () => ok(server.address().port)));

let sim;
let simUrl;
let env;

async function startApp(overrides = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'breakapi-sim-'));
  // The sim runs on loopback here, so this app allows local targets. Playground projects still get no
  // loopback exemption of their own: they are trusted only for the configured sim host.
  const app = createApp({
    config: loadConfig({}, { dataDir, quiet: true, allowLocalTargets: true, allowPrivateTargets: false, simUrl, simControlKey: KEY, ...overrides }),
    log: quiet,
  });
  return { app, dataDir, base: `http://127.0.0.1:${await listen(app.server)}` };
}
const stopApp = async (e) => {
  await e.app.lab.shutdown();
  e.app.server.close();
  rmSync(e.dataDir, { recursive: true, force: true });
};

const call = async (base, method, path, body) => {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-breakapi': '1' }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json().catch(() => null) };
};

async function finished(app, id) {
  for (let i = 0; i < 1200; i++) {
    const v = app.lab.view(id);
    if (v.status === 'finished') return v;
    await sleep(25);
  }
  throw new Error('run did not finish');
}
async function playground(app, input) {
  const r = await app.lab.startPlayground(input);
  assert.ok(r.id, JSON.stringify(r));
  return finished(app, r.id);
}
async function retest(app, id, input) {
  const r = await app.lab.retest(id, input);
  assert.ok(r.id, JSON.stringify(r));
  return finished(app, id);
}
const describeFindings = (phase) => phase.scan.findings.map((f) => `${f.title} @ ${f.endpoint}`).join(' | ');

before(async () => {
  if (skip) return;
  const { createSimServer } = await import(pathToFileURL(simEntry).href);
  sim = createSimServer({ controlKey: KEY, log: quiet });
  simUrl = `http://127.0.0.1:${await listen(sim)}`;
  env = await startApp();
});
after(async () => {
  if (skip) return;
  await stopApp(env);
  sim.close();
});

test('the lab page lists the sim catalog, without its detection signatures', { skip }, async () => {
  const { status, body } = await call(env.base, 'GET', '/api/lab');
  assert.equal(status, 200);
  assert.equal(body.playground.available, true);
  assert.ok(body.playground.vulns.length >= 7);
  assert.ok(body.playground.presets.some((p) => p.id === 'hardened'));
  for (const v of body.playground.vulns) assert.equal(v.detects, undefined);
  assert.ok(body.examples.length >= 14, 'the built-in examples are still there');
});

test('requests choose catalog ids only: bad input is refused and addresses are ignored', { skip }, async () => {
  for (const bad of [{ preset: 'nope' }, { vulns: ['authz.nope'] }, { vulns: ['__proto__'] }, { vulns: 'config.cors-reflect' }, { vulns: [{}] }]) {
    const r = await call(env.base, 'POST', '/api/lab/runs', bad);
    assert.equal(r.status, 400, JSON.stringify(bad));
  }
  const other = 'http://127.0.0.1:9/elsewhere';
  const r = await call(env.base, 'POST', '/api/lab/runs', { preset: 'hardened', baseUrl: other, simUrl: other, sandbox: { baseUrl: other }, host: '127.0.0.1:9' });
  assert.equal(r.status, 200);
  const v = await finished(env.app, r.body.id);
  assert.ok(v.sandbox.baseUrl.startsWith(`${simUrl}/s/sbx_`), v.sandbox.baseUrl);
  assert.ok(!JSON.stringify(v).includes('127.0.0.1:9/'));
  assert.ok(!JSON.stringify(v).includes(KEY), 'the control key never reaches a visitor');
});

test('hardened sandbox: breakAPI reports nothing, and only reads were sent', { skip }, async () => {
  const [p] = (await playground(env.app, { preset: 'hardened' })).phases;
  assert.equal(p.scan.status, 'completed', JSON.stringify(p.scan.problems || p.scan.stopReason));
  assert.equal(p.scan.findings.length, 0, describeFindings(p));
  assert.ok(p.score.rows.every((r) => r.outcome === 'clean'));
  assert.equal(p.score.recall, null);
  assert.ok(p.seen.requests > 0 && p.seen.requests <= p.scan.requestsSent, JSON.stringify(p.seen));
  assert.equal(p.seen.writes, 0);
  assert.equal(p.seen.deletes, 0);
});

test('each vulnerability planted alone is detected, with no false alarms', { skip }, async () => {
  const { playground: pg } = (await call(env.base, 'GET', '/api/lab')).body;
  for (const v of pg.vulns) {
    const [p] = (await playground(env.app, { vulns: [v.id] })).phases;
    assert.equal(p.scan.status, 'completed', v.id);
    const row = p.score.rows.find((r) => r.id === v.id);
    assert.equal(row.outcome, 'hit', `${v.id}: ${describeFindings(p)}`);
    assert.equal(p.score.falseAlarms, 0, `${v.id}: ${describeFindings(p)}`);
    assert.deepEqual(p.score.unexplained, [], v.id);
  }
});

test('every preset scores full recall', { skip }, async () => {
  const { playground: pg } = (await call(env.base, 'GET', '/api/lab')).body;
  for (const preset of pg.presets) {
    const [p] = (await playground(env.app, { preset: preset.id })).phases;
    assert.ok(p.score.recall === null || p.score.recall === 1, `${preset.id}: ${describeFindings(p)}`);
    assert.equal(p.score.falseAlarms, 0, preset.id);
  }
});

test('retest re-plants the sandbox, swaps the re-keyed tokens and compares with the last scan', { skip }, async () => {
  let v = await playground(env.app, { preset: 'hardened' });
  // If the accounts were not replaced after re-keying, every authenticated check would fail and recall drop.
  v = await retest(env.app, v.id, { preset: 'everything' });
  assert.equal(v.phases[1].score.recall, 1, describeFindings(v.phases[1]));
  assert.ok(v.phases[1].scan.comparison.new.length > 0);
  v = await retest(env.app, v.id, { preset: 'hardened' });
  const last = v.phases[2];
  assert.equal(last.scan.findings.length, 0, describeFindings(last));
  assert.ok(last.scan.comparison.fixed.some((f) => f.title === 'Cross-account data access (BOLA/IDOR)'));
  assert.equal(last.scan.comparison.new.length, 0);
  const busy = await env.app.lab.retest(v.id, { preset: 'nope' });
  assert.equal(busy.error, 400);
});

test('retest rebuilds an expired sandbox from the same seed', { skip }, async () => {
  const v = await playground(env.app, { vulns: ['authz.bola-documents'] });
  const first = v.sandbox.baseUrl;
  const oldId = first.split('/').pop();
  assert.equal((await fetch(`${simUrl}/_control/sandboxes/${oldId}`, { method: 'DELETE', headers: { authorization: `Bearer ${KEY}` } })).status, 204);
  const after = await retest(env.app, v.id, { vulns: ['authz.bola-documents'] });
  assert.notEqual(after.sandbox.baseUrl, first);
  assert.equal(after.phases[1].score.recall, 1, describeFindings(after.phases[1]));
  assert.equal(after.phases[1].scan.comparison.stillOpen.length, after.phases[0].scan.findings.length, 'same seed, same findings');
});

test('the report says the target was the simulation', { skip }, async () => {
  const v = await playground(env.app, { vulns: ['config.cors-reflect'] });
  const html = await (await fetch(`${env.base}/reports/lab/${v.id}/0`)).text();
  assert.match(html, /simulation backend/);
  assert.match(html, /no real system was contacted/);
});

test('shutting down removes the sandboxes the lab created', { skip }, async () => {
  const e = await startApp();
  await playground(e.app, { preset: 'hardened' });
  const before = sim.sandboxes.size();
  await stopApp(e);
  assert.equal(sim.sandboxes.size(), before - 1);
});

test('an unreachable or misconfigured sim turns the playground off without leaking the key', { skip }, async () => {
  for (const overrides of [{ simUrl: 'http://127.0.0.1:9' }, { simControlKey: 'wrong-key-wrong-key-wrong-key-00' }]) {
    const e = await startApp(overrides);
    try {
      const lab = (await call(e.base, 'GET', '/api/lab')).body;
      assert.equal(lab.playground.available, false);
      const r = await call(e.base, 'POST', '/api/lab/runs', { preset: 'hardened' });
      assert.equal(r.status, 503);
      assert.ok(!JSON.stringify(r.body).includes(KEY) && !JSON.stringify(r.body).includes('wrong-key'));
    } finally {
      await stopApp(e);
    }
  }
});

test('only an in-memory lab project can carry the simulation exemption', () => {
  assert.equal(isSimEntry({ lab: true, simHost: 'sim.example.com' }, 'SIM.example.com'), true);
  assert.equal(isSimEntry({ simHost: 'sim.example.com' }, 'sim.example.com'), false, 'a real project never qualifies');
  assert.equal(isSimEntry({ lab: true, simHost: 'sim.example.com' }, 'other.example.com'), false);
  assert.equal(isSimEntry({ lab: true }, 'sim.example.com'), false);
});

// --- Embedded mode: the sim runs inside breakAPI (one Replit project), reached at <public URL>/sim ---

async function startEmbedded(overrides = {}) {
  // The public address has to be known before the app is created, so reserve a free port first.
  const probe = (await import('node:http')).createServer();
  const port = await listen(probe);
  await new Promise((ok) => probe.close(ok));
  const dataDir = mkdtempSync(join(tmpdir(), 'breakapi-embed-'));
  const publicUrl = `http://127.0.0.1:${port}`;
  const app = createApp({
    config: loadConfig({}, { dataDir, quiet: true, allowLocalTargets: true, allowPrivateTargets: false, simEmbedDir: simDir, simPublicUrl: publicUrl, ...overrides }),
    log: quiet,
  });
  await new Promise((ok) => app.server.listen(port, '127.0.0.1', ok));
  return { app, dataDir, base: publicUrl, ready: await app.ready };
}
const stopEmbedded = async (e) => {
  await e.app.shutdown();
  e.app.server.close();
  rmSync(e.dataDir, { recursive: true, force: true });
};

test('embedded: sandboxes are reached at /sim on breakAPI itself, and scoring still works', { skip }, async () => {
  const e = await startEmbedded();
  try {
    assert.equal(e.ready, true);
    const lab = (await call(e.base, 'GET', '/api/lab')).body;
    assert.equal(lab.playground.available, true);
    const hardened = await playground(e.app, { preset: 'hardened' });
    assert.ok(hardened.sandbox.baseUrl.startsWith(`${e.base}/sim/s/sbx_`), hardened.sandbox.baseUrl);
    const [h] = hardened.phases;
    assert.equal(h.scan.status, 'completed', JSON.stringify(h.scan.problems || h.scan.stopReason));
    assert.equal(h.scan.findings.length, 0, describeFindings(h));
    const leaky = (await playground(e.app, { preset: 'everything' })).phases[0];
    assert.equal(leaky.score.recall, 1, describeFindings(leaky));
    assert.equal(leaky.score.falseAlarms, 0);
    assert.deepEqual(leaky.score.unexplained, []);
  } finally {
    await stopEmbedded(e);
  }
});

test('embedded: only sandbox traffic is forwarded, with the sim\'s own headers', { skip }, async () => {
  const e = await startEmbedded();
  try {
    const key = e.app.config.simControlKey;
    assert.equal(key, '', 'no key is configured: the embedded sim makes its own');
    for (const path of ['/sim/_control/catalog', '/sim/_control/sandboxes', '/sim/healthz', '/sim/nope', '/sim/s', '/sim/s/..%2f_control/catalog']) {
      const r = await fetch(`${e.base}${path}`, { headers: { authorization: 'Bearer anything' } });
      assert.equal(r.status, 404, path);
    }
    assert.equal((await fetch(`${e.base}/sim/`)).status, 200);
    assert.equal((await fetch(`${e.base}/sim`)).status, 200);
    assert.equal((await fetch(`${e.base}/sim/s/sbx_doesnotexist000000/v1/me`)).status, 404);
    // breakAPI's own pages keep their security headers; sim responses carry the sim's.
    const own = await fetch(`${e.base}/api/healthz`);
    assert.ok(own.headers.get('content-security-policy'));
    const simRoot = await fetch(`${e.base}/sim/`);
    assert.equal(simRoot.headers.get('content-security-policy'), null);
    assert.equal(simRoot.headers.get('x-content-type-options'), 'nosniff');
    // A planted CORS flaw must reach the scanner untouched.
    const v = await playground(e.app, { vulns: ['config.cors-reflect'] });
    assert.equal(v.phases[0].score.rows.find((r) => r.id === 'config.cors-reflect').outcome, 'hit');
  } finally {
    await stopEmbedded(e);
  }
});

test('embedded: shutting down removes sandboxes and stops the sim', { skip }, async () => {
  const e = await startEmbedded();
  try {
    const v = await playground(e.app, { preset: 'hardened' });
    const id = v.sandbox.baseUrl.split('/').pop();
    assert.equal((await fetch(`${e.base}/sim/s/${id}/`)).status, 200);
    await e.app.shutdown();
    assert.equal((await fetch(`${e.base}/sim/s/${id}/`)).status, 503, 'the embedded sim is gone');
  } finally {
    e.app.server.close();
    rmSync(e.dataDir, { recursive: true, force: true });
  }
});

test('embedded: a missing checkout turns the playground off and nothing else', { skip }, async () => {
  const e = await startEmbedded({ simEmbedDir: join(tmpdir(), 'no-such-sim-checkout') });
  try {
    assert.equal(e.ready, false);
    const lab = (await call(e.base, 'GET', '/api/lab')).body;
    assert.equal(lab.playground.available, false);
    assert.ok(lab.examples.length >= 14);
    assert.equal((await call(e.base, 'POST', '/api/lab/runs', { preset: 'hardened' })).status, 503);
    assert.equal((await fetch(`${e.base}/sim/`)).status, 503);
  } finally {
    await stopEmbedded(e);
  }
});
