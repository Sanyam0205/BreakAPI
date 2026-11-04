import { readFileSync } from 'node:fs';
import { createDemoServer, demoTokens } from '../demo/vulnerable-api.js';
import { encrypt } from './crypto.js';
import { importSpec } from './importers.js';
import { createScan, runScan, running } from './scanner.js';
import { hashUndertaking, UNDERTAKING_VERSION } from './undertaking.js';
import { randomToken } from './auth.js';
import { ALL_TESTS, TEST_LABELS } from './scope.js';
import { nowIso, sleep } from './util.js';
import { resolvePlayground, catalogTests, scoreRun, LabConfigError } from './labscore.js';

// The demo lab has two kinds of run, and neither takes a target from a visitor:
//  - examples: fixed scenarios against the built-in demo API, started on a loopback port per run;
//  - playground: a sandbox on the separately hosted simulation backend (BREAKAPI_SIM_URL) with the
//    vulnerabilities the visitor picked from its catalog. Visitors choose catalog ids and nothing else;
//    the sandbox address is built from server configuration, never from a request or a sim response.
const MAX_ACTIVE = 2;
const MAX_PHASES = 6;
const MAX_KEPT = 30;
const KEEP_MS = 3600_000;
const SPEC = new URL('../demo/openapi.json', import.meta.url);

const CONTROLS = { maxRequests: 400, rps: 40, burstRps: 80, rateLimitBurst: 30, timeoutMs: 5000, stopOnErrorStreak: 10, exclusions: [], windowStart: null, windowEnd: null, monitoringContact: '', maxWrites: 50, maxDurationMs: 120_000 };
const WRITE_KINDS = ['signup', 'login', 'order'];

/**
 * group: 'testing' shows a kind of API test; 'safety' shows a control that limits breakAPI itself.
 * Each phase is one scan. Phases of one example share a project, so a later one is compared with the one before.
 */
export const EXAMPLES = [
  {
    id: 'config', group: 'testing', title: 'Transport, CORS and headers', tests: ['config'],
    summary: 'Is the API configured safely before anyone even logs in?',
    what: 'Reflected CORS origins with credentials, missing security headers, and software versions leaking in headers.',
    how: 'Sends ordinary GET requests, some with a foreign Origin header, and reads the response headers.',
    expect: '4 findings: 1 high (CORS reflects any origin with credentials), 1 medium, 2 low.',
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'exposure', group: 'testing', title: 'Exposed files and diagnostics', tests: ['exposure'],
    summary: 'Is anything readable that should never have been published?',
    what: 'Secret files such as .env, published API specs and debug or admin paths.',
    how: 'Requests a short list of well-known paths without credentials and checks what each one returns.',
    expect: '2 findings: 1 high (readable .env file, with fake secrets) and 1 info (public API spec).',
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'authn', group: 'testing', title: 'Broken authentication', tests: ['authn'],
    summary: 'Can someone get in with no token, or with a forged one?',
    what: 'Protected routes that answer without a token, unsigned (alg=none) tokens, and guessable signing keys.',
    how: 'Replays each protected request with no token, then with tampered copies of a test account\'s token.',
    expect: '9 findings: 2 critical (guessable JWT key, alg=none accepted), 1 high (invoice route with no login) and 6 low data-quality indicators.',
    accounts: ['alice'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'authz', group: 'testing', title: 'Cross-account access (IDOR)', tests: ['authz'],
    summary: 'Can one user read another user\'s data, or reach admin functions?',
    what: 'Object-level access between two users, and admin routes reachable by an ordinary account.',
    how: 'Signs in as alice, requests bob\'s records by id, and compares the answer with bob\'s own. Then tries admin routes as alice.',
    expect: '4 findings: 3 high (2 cross-account reads, 1 admin route) and 1 info (sequential ids).',
    accounts: ['alice', 'bob'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'input', group: 'testing', title: 'Input handling', tests: ['input'],
    summary: 'Does hostile input change how the server behaves?',
    what: 'SQL error messages, stack traces and reflected script tags.',
    how: 'Puts harmless marker strings and quote characters into query parameters and looks for them in the response. Nothing is modified.',
    expect: '3 findings: 1 high (SQL error on /api/search), 2 medium (stack trace, reflected script on /api/greet).',
    accounts: ['alice'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'validation', group: 'testing', title: 'Server-side data validation', tests: ['validation'], writes: true,
    summary: 'Does the server check what it stores, or trust the client?',
    what: 'Malformed emails, wrong types, out-of-range numbers, and privileged fields set by the client (mass assignment).',
    how: 'Sends synthetic records with fake .invalid addresses to endpoints opted in to writes, then checks whether they were accepted.',
    expect: '8 findings: 1 high (role set through signup), 1 medium (malformed email), 6 low.',
    accounts: ['alice', 'bob'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'identity', group: 'testing', title: 'Signup, verification and enumeration', tests: ['identity'], writes: true,
    summary: 'Can accounts be abused, or discovered from the outside?',
    what: 'Sessions issued before email verification, duplicate accounts, weak passwords, and login answers that reveal who has an account.',
    how: 'Creates synthetic accounts and compares login answers for a known and an unknown email.',
    expect: '5 findings: 1 high (access before verification), 3 medium (duplicate account, weak password, enumeration), 1 low.',
    accounts: ['alice', 'bob'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'logic', group: 'testing', title: 'Business logic', tests: ['logic'], writes: true,
    summary: 'Can valid-looking requests break the rules of the business?',
    what: 'Negative or huge quantities, prices supplied by the client, and replayed orders.',
    how: 'Places synthetic orders with altered amounts, then submits one twice and compares the results.',
    expect: '6 findings: 2 high (negative quantity, client-set price), 1 medium, 3 low.',
    accounts: ['alice', 'bob'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'ratelimit', group: 'testing', title: 'Rate limiting, before and after', tests: ['ratelimit'],
    summary: 'Does the API slow down a client that sends too much?',
    what: 'Whether a short, bounded burst ever gets a 429 answer.',
    how: 'Sends the same bounded burst twice: first to an API with no limit, then to one that allows 5 requests per second.',
    expect: 'Phase 1 finds no rate limit (1 medium). Phase 2 has no findings and the retest lists it as fixed.',
    accounts: ['alice'],
    phases: [{ label: 'No rate limit' }, { label: 'Limit of 5 requests per second', server: { rateLimit: 5 } }],
  },
  {
    id: 'retest', group: 'testing', title: 'Fix and retest', tests: ['config', 'exposure', 'authn', 'authz', 'input'],
    summary: 'After a fix ships, which findings actually went away?',
    what: 'The comparison between two scans: fixed, still open, and new.',
    how: 'Scans the vulnerable API, then the same API with its main flaws patched, and compares the two.',
    expect: 'Phase 1 has 23 findings. Phase 2 has 10: the retest shows 13 fixed and 10 still open, because only some flaws were patched.',
    accounts: ['alice', 'bob'],
    phases: [{ label: 'Before the fix' }, { label: 'After the fix', server: { fixed: true } }],
  },
  {
    id: 'full', group: 'testing', title: 'Full assessment', tests: ALL_TESTS, writes: true,
    summary: 'Every check together, the way a real project would run them.',
    what: 'All nine test categories in one scan, with the report you would hand to a team.',
    how: 'Runs configuration, exposure, authentication, authorization, input, validation, identity, logic and rate-limit checks in order.',
    expect: '43 findings from about 108 requests, 34 of them writes. Open the report for evidence, impact and a fix for each.',
    accounts: ['alice', 'bob'],
    phases: [{ label: 'Vulnerable API' }],
  },
  {
    id: 'consent', group: 'safety', title: 'Consent wall', tests: ['config'],
    summary: 'A scan that has no valid authorization never sends a request.',
    what: 'The pre-flight check that runs before any traffic.',
    how: 'Tries three scans: no authorization, an expired one, and a target outside the authorized scope.',
    expect: 'All three are blocked with the reason listed. The target counts 0 requests.',
    phases: [
      { label: 'No authorization', authorization: 'none' },
      { label: 'Expired authorization', authorization: 'expired' },
      { label: 'Target out of scope', authorization: 'out-of-scope' },
    ],
  },
  {
    id: 'budget', group: 'safety', title: 'Request budget', tests: ['config', 'exposure', 'authn', 'authz', 'input'],
    summary: 'A scan stops itself when it reaches its limit.',
    what: 'The per-scan request budget, enforced in the client every request goes through.',
    how: 'Starts a broad scan with a budget of only 12 requests.',
    expect: 'The scan ends as halted after 12 requests, and unfinished checks are marked incomplete.',
    accounts: ['alice', 'bob'],
    controls: { maxRequests: 12 },
    phases: [{ label: 'Budget of 12 requests' }],
  },
  {
    id: 'writes', group: 'safety', title: 'Write protection', tests: ['validation', 'identity', 'logic'],
    summary: 'Nothing is written without two separate permissions.',
    what: 'The global write switch plus the per-endpoint opt-in, both needed before any POST.',
    how: 'Runs the write-based checks three times: both off, only the switch on, then both on.',
    expect: 'The target counts 0 writes in the first two phases and some in the third. DELETE stays at 0 throughout.',
    accounts: ['alice', 'bob'],
    phases: [
      { label: 'Switch off, no opt-in' },
      { label: 'Switch on, no opt-in', writeSwitch: true },
      { label: 'Switch on, endpoints opted in', writeSwitch: true, optIn: true },
    ],
  },
];

const publicExample = ({ id, group, title, summary, what, how, expect, tests, phases }) => ({
  id, group, title, summary, what, how, expect,
  tests: tests.map((t) => TEST_LABELS[t]),
  phases: phases.map((p) => p.label),
});

function buildAuthorization(ex, phase, host) {
  const kind = phase.authorization;
  if (kind === 'none') return null;
  const now = Date.now();
  return {
    id: `auth_${randomToken(6)}`,
    authorizerName: 'breakAPI demo lab',
    authorizerEmail: 'demo-lab@breakapi.invalid',
    relationship: 'owner',
    allowedHosts: [kind === 'out-of-scope' ? 'api.other-company.invalid' : host],
    allowedTests: ex.tests,
    allowWriteMethods: !!(ex.writes || phase.writeSwitch),
    recordedAt: nowIso(),
    confirmedAt: nowIso(),
    confirmedVia: 'generated by the demo lab',
    expiresAt: new Date(kind === 'expired' ? now - 86400_000 : now + 3600_000).toISOString(),
    attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true },
    undertaking: { version: UNDERTAKING_VERSION, sha256: hashUndertaking(), acceptedAt: nowIso(), typedName: 'breakAPI demo lab' },
  };
}

function buildProject(ex, runId, key) {
  const tokens = demoTokens();
  const ids = { alice: '1', bob: '2' };
  return {
    id: `labp_${runId}`,
    lab: true,
    name: `Demo lab: ${ex.title}`,
    createdAt: nowIso(),
    members: [],
    audit: [],
    verifiedHosts: [],
    controls: { ...CONTROLS, ...ex.controls },
    target: { baseUrl: '', endpoints: importSpec('openapi', readFileSync(SPEC, 'utf8')).endpoints },
    accounts: (ex.accounts || []).map((label) => ({
      id: `acct_${label}`, label, role: 'user', authType: 'bearer', secretEnc: encrypt(key, tokens[label]), secretHint: `${label}'s demo token`, resourceIds: { id: ids[label], email: `${label}@demo.test` }, createdAt: nowIso(),
    })),
  };
}

const ACCOUNT_LABELS = new Set(['alice', 'bob', 'root']);

/** Sandbox accounts → encrypted lab accounts. The sim is operator-run, but its answer is still checked. */
function sandboxAccounts(box, key) {
  return (Array.isArray(box?.accounts) ? box.accounts : [])
    .filter((a) => ACCOUNT_LABELS.has(a?.label) && typeof a.token === 'string' && a.token.length < 4096)
    .map((a) => ({
      id: `acct_${a.label}`,
      label: a.label,
      role: a.role === 'admin' ? 'admin' : 'user',
      authType: 'bearer',
      secretEnc: encrypt(key, a.token),
      secretHint: `${a.label}'s sandbox token`,
      resourceIds: Object.fromEntries(Object.entries(a.resourceIds || {}).filter(([k, v]) => /^\w{1,40}$/.test(k) && typeof v === 'string' && v.length < 200)),
      createdAt: nowIso(),
    }));
}

const SANDBOX_ID = /^sbx_[A-Za-z0-9_-]{16}$/;

export function createLab({ key, log = console, sim = null, simUrl = '', dailyRuns = 300 }) {
  // In memory on purpose: lab runs are never mixed with real projects, accounts or the data file.
  const store = { data: { projects: {}, scans: {} }, save() {}, saveNow() {} };
  const runs = new Map();
  const simOrigin = simUrl ? new URL(simUrl).origin : '';
  let starting = 0;
  const daily = { day: '', count: 0 };

  const active = () => [...runs.values()].filter((r) => r.status === 'running').length + starting;
  const busy = () => (active() >= MAX_ACTIVE ? { error: 429, message: 'The demo lab is busy with other runs. Try again in a moment.' } : null);
  /** Counts one run against the server-wide daily cap; null when allowed. */
  const takeDaily = () => {
    const today = new Date().toISOString().slice(0, 10);
    if (daily.day !== today) Object.assign(daily, { day: today, count: 0 });
    if (daily.count >= dailyRuns) return { error: 429, message: 'The demo lab has reached its limit for today. Try again tomorrow.' };
    daily.count++;
    return null;
  };
  const simFailure = (err) => {
    if (err?.status === 400) return { error: 400, message: err.message };
    log.error?.('simulation backend call failed', err);
    return { error: 503, message: 'The simulation backend is not available right now. Try again in a moment.' };
  };

  const forget = (run) => {
    for (const p of run.phases) if (p.scanId) delete store.data.scans[p.scanId];
    delete store.data.projects[run.projectId];
    runs.delete(run.id);
    if (run.sandbox && sim) sim.remove(run.sandbox.id).catch(() => {});
  };
  const prune = () => {
    const finished = [...runs.values()].filter((r) => r.status === 'finished');
    for (const r of finished) if (Date.now() - new Date(r.finishedAt) > KEEP_MS) forget(r);
    const left = finished.filter((r) => runs.has(r.id));
    while (left.length > MAX_KEPT) forget(left.shift());
  };

  const execute = async (run, ex) => {
    const project = store.data.projects[run.projectId];
    let port = 0;
    let previousScanId = null;
    for (const [i, phase] of ex.phases.entries()) {
      if (run.stopRequested) break;
      const target = createDemoServer(phase.server || {});
      // Later phases keep the same port, so hosts in scope and retest comparisons stay the same.
      await new Promise((resolve, reject) => {
        target.once('error', reject);
        target.listen(port, '127.0.0.1', resolve);
      });
      port = target.address().port;
      const host = `127.0.0.1:${port}`;
      try {
        project.authorization = buildAuthorization(ex, phase, host);
        project.target.baseUrl = `http://${host}`;
        for (const e of project.target.endpoints) {
          e.syntheticWrites = !!(phase.optIn || ex.writes) && WRITE_KINDS.includes(e.kind);
        }
        const scan = createScan(store, project, { previousScanId });
        scan.startedBy = { email: 'demo-lab@breakapi.invalid', name: 'Demo lab', emailVerifiedAt: scan.createdAt };
        scan.verificationSnapshot = [{ host, local: true }];
        run.phases[i].scanId = scan.id;
        run.phases[i].seen = target.seen;
        await runScan({ store, key }, scan.id);
        if (ex.phases.length > 1 && !phase.authorization) previousScanId = scan.id;
      } finally {
        target.closeAllConnections();
        await new Promise((resolve) => target.close(resolve));
      }
    }
  };

  const start = (exampleId) => {
    const ex = EXAMPLES.find((x) => x.id === exampleId);
    if (!ex) return { error: 404, message: 'There is no example with that id.' };
    prune();
    const refused = busy() || takeDaily();
    if (refused) return refused;
    const id = randomToken(16);
    const project = buildProject(ex, randomToken(6).replace(/-/g, '_'), key);
    store.data.projects[project.id] = project;
    const run = { id, kind: 'example', exampleId: ex.id, title: ex.title, projectId: project.id, status: 'running', createdAt: nowIso(), phases: ex.phases.map((p) => ({ label: p.label })) };
    runs.set(id, run);
    execute(run, ex)
      .catch((err) => {
        run.error = 'The demo run failed unexpectedly. Try it again.';
        log.error?.('demo lab run failed', err);
      })
      .finally(() => {
        run.status = 'finished';
        run.finishedAt = nowIso();
      });
    return { id };
  };

  // ---------- playground: sandboxes on the simulation backend ----------

  const sandboxBase = (sandboxId) => `${simOrigin}/s/${sandboxId}`;

  /** Catalog for the lab page, or why the playground is unavailable. */
  const playground = async () => {
    if (!sim) return { available: false, reason: 'The simulation playground is not set up on this server.' };
    try {
      const c = await sim.catalog();
      return {
        available: true,
        catalogVersion: c.version,
        tests: catalogTests(c).map((t) => ({ id: t, label: TEST_LABELS[t] || t })),
        vulns: c.vulns.map(({ id, test, title, severity, summary, patched }) => ({ id, test, title, severity, summary, patched })),
        presets: c.presets.map(({ id, title, summary, vulns }) => ({ id, title, summary, vulns })),
      };
    } catch (err) {
      log.error?.('simulation catalog unavailable', err);
      return { available: false, reason: 'The simulation backend is not reachable right now.' };
    }
  };

  /** Scans the run's sandbox once more as a new phase; later phases are compared with the one before. */
  const runPlaygroundPhase = async (run, index, seenBefore) => {
    const project = store.data.projects[run.projectId];
    const phase = run.phases[index];
    const previous = run.phases.slice(0, index).reverse().find((p) => p.scanId && store.data.scans[p.scanId]?.status === 'completed');
    const scan = createScan(store, project, { previousScanId: previous?.scanId });
    scan.startedBy = { email: 'demo-lab@breakapi.invalid', name: 'Demo lab', emailVerifiedAt: scan.createdAt };
    scan.verificationSnapshot = [{ host: project.simHost, local: false, sim: true }];
    phase.scanId = scan.id;
    await runScan({ store, key }, scan.id);
    try {
      const after = await sim.get(run.sandbox.id);
      const before = seenBefore || { requests: 0, writes: 0, deletes: 0 };
      phase.seen = Object.fromEntries(['requests', 'writes', 'deletes'].map((k) => [k, Math.max(0, (after.seen?.[k] || 0) - (before[k] || 0))]));
    } catch {
      phase.seen = null;
    }
    phase.score = scoreRun(run.catalog, { planted: phase.vulns, findings: scan.findings, tests: project.authorization.allowedTests });
  };

  const launch = (run, fn) => {
    run.status = 'running';
    delete run.finishedAt;
    fn()
      .catch((err) => {
        run.error = 'The demo run failed unexpectedly. Try it again.';
        log.error?.('demo lab run failed', err);
      })
      .finally(() => {
        run.status = 'finished';
        run.finishedAt = nowIso();
      });
  };

  const presetTitle = (catalog, input, vulns) => catalog.presets.find((p) => p.id === input.preset)?.title
    || (vulns.length ? `Custom scenario (${vulns.length} planted)` : 'Custom scenario (nothing planted)');

  /** input: { preset } or { vulns: [catalog ids] }. Nothing else from the request is read. */
  const startPlayground = async (input) => {
    if (!sim) return { error: 404, message: 'The simulation playground is not set up on this server.' };
    prune();
    let refused = busy();
    if (refused) return refused;
    let catalog;
    let vulns;
    try {
      catalog = await sim.catalog();
      vulns = resolvePlayground(catalog, input);
    } catch (err) {
      if (err instanceof LabConfigError) return { error: 400, message: err.message };
      return simFailure(err);
    }
    refused = busy() || takeDaily();
    if (refused) return refused;
    starting++;
    let box;
    let project;
    try {
      box = await sim.create(vulns);
      if (!SANDBOX_ID.test(String(box?.id))) throw new Error('the simulation returned no sandbox id');
      const spec = await sim.spec(box.id);
      const tests = catalogTests(catalog);
      const baseUrl = sandboxBase(box.id);
      project = {
        id: `labp_${randomToken(6).replace(/-/g, '_')}`,
        lab: true,
        simHost: sim.host,
        name: `Demo lab playground: ${presetTitle(catalog, input, vulns)}`,
        createdAt: nowIso(),
        members: [],
        audit: [],
        verifiedHosts: [],
        // Read-only checks only: the sandbox has no write routes yet, so no write is ever authorized.
        controls: { ...CONTROLS, maxWrites: 0 },
        target: { baseUrl, endpoints: importSpec('openapi', spec).endpoints },
        accounts: sandboxAccounts(box, key),
      };
      project.authorization = buildAuthorization({ tests, writes: false }, {}, sim.host);
    } catch (err) {
      if (box?.id && SANDBOX_ID.test(box.id)) sim.remove(box.id).catch(() => {});
      return simFailure(err);
    } finally {
      starting--;
    }
    store.data.projects[project.id] = project;
    const id = randomToken(16);
    const run = {
      id,
      kind: 'playground',
      exampleId: 'playground',
      title: presetTitle(catalog, input, vulns),
      projectId: project.id,
      createdAt: nowIso(),
      catalog,
      sandbox: { id: box.id, seed: box.seed, expiresAt: box.expiresAt },
      phases: [{ label: 'Scan', vulns }],
    };
    runs.set(id, run);
    launch(run, () => runPlaygroundPhase(run, 0, box.seen));
    return { id };
  };

  /** Re-plants the sandbox with a new set of flaws and scans it again, compared with the last scan. */
  const retest = async (id, input) => {
    const run = runs.get(id);
    if (!run || run.kind !== 'playground') return { error: 404, message: 'This run is no longer available.' };
    if (run.status === 'running' || run.retesting) return { error: 409, message: 'This run is still scanning. Wait for it to finish.' };
    if (run.phases.length >= MAX_PHASES) return { error: 409, message: `A run can have at most ${MAX_PHASES} scans. Start a new one.` };
    let vulns;
    try {
      vulns = resolvePlayground(run.catalog, input);
    } catch (err) {
      if (err instanceof LabConfigError) return { error: 400, message: err.message };
      throw err;
    }
    const refused = busy() || takeDaily();
    if (refused) return refused;
    const project = store.data.projects[run.projectId];
    starting++;
    run.retesting = true;
    let box;
    try {
      try {
        box = await sim.configure(run.sandbox.id, vulns);
      } catch (err) {
        if (err?.status !== 404) throw err;
        // The sandbox expired or the sim restarted: rebuild it from the same seed, so ids stay the same.
        box = await sim.create(vulns, run.sandbox.seed);
        if (!SANDBOX_ID.test(String(box?.id))) throw new Error('the simulation returned no sandbox id');
        run.sandbox.id = box.id;
        project.target.baseUrl = sandboxBase(box.id);
      }
      // Reconfiguring re-keys the sandbox: the old tokens stop working, so the accounts are replaced.
      project.accounts = sandboxAccounts(box, key);
      run.sandbox.expiresAt = box.expiresAt;
    } catch (err) {
      return simFailure(err);
    } finally {
      starting--;
      run.retesting = false;
    }
    if (!runs.has(id)) return { error: 404, message: 'This run is no longer available.' };
    const index = run.phases.push({ label: `Retest ${run.phases.length}`, vulns }) - 1;
    launch(run, () => runPlaygroundPhase(run, index, box.seen));
    return { id, phase: index };
  };

  const view = (id) => {
    const run = runs.get(id);
    if (!run) return null;
    const { id: runId, kind, exampleId, title, status, createdAt, finishedAt, error, stopRequested } = run;
    return {
      id: runId, kind, exampleId, title, status, createdAt, finishedAt, error, stopRequested: !!stopRequested,
      ...(run.sandbox ? { sandbox: { baseUrl: sandboxBase(run.sandbox.id), expiresAt: run.sandbox.expiresAt }, catalogVersion: run.catalog.version, maxPhases: MAX_PHASES } : {}),
      phases: run.phases.map((p) => {
        const s = p.scanId && store.data.scans[p.scanId];
        return {
          label: p.label,
          ...(p.vulns ? { vulns: p.vulns, score: p.score || null } : {}),
          seen: p.seen || null,
          scan: s ? {
            id: s.id, status: s.status, startedAt: s.startedAt, finishedAt: s.finishedAt, requestsSent: s.requestsSent, writesSent: s.writesSent || 0,
            maxRequests: store.data.projects[run.projectId].controls.maxRequests,
            stopReason: s.stopReason, problems: s.problems, comparison: s.comparison, checks: s.checks, findings: s.findings, log: s.log,
          } : null,
        };
      }),
    };
  };

  const stop = (id) => {
    const run = runs.get(id);
    if (!run) return false;
    run.stopRequested = true;
    for (const p of run.phases) {
      const ctl = p.scanId && running.get(p.scanId);
      if (ctl) Object.assign(ctl, { stopReason: 'Stopped from the demo lab.', userStopped: true });
    }
    return true;
  };

  /** The project and scan for a report page, or null. */
  const reportData = (id, phase) => {
    const run = runs.get(id);
    const scan = run?.phases[phase]?.scanId && store.data.scans[run.phases[phase].scanId];
    return scan ? { project: store.data.projects[run.projectId], scan } : null;
  };

  /** Stops every run and waits for them to end (tests and shutdown). */
  const shutdown = async () => {
    for (const id of runs.keys()) stop(id);
    while ([...runs.values()].some((r) => r.status === 'running')) await sleep(50);
    // Best effort: sandboxes also expire on their own.
    if (sim) await Promise.allSettled([...runs.values()].filter((r) => r.sandbox).map((r) => sim.remove(r.sandbox.id)));
  };

  return { examples: () => EXAMPLES.map(publicExample), playground, start, startPlayground, retest, view, stop, reportData, shutdown };
}
