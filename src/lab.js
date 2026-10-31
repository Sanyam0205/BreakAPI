import { readFileSync } from 'node:fs';
import { createDemoServer, demoTokens } from '../demo/vulnerable-api.js';
import { encrypt } from './crypto.js';
import { importSpec } from './importers.js';
import { createScan, runScan, running } from './scanner.js';
import { hashUndertaking, UNDERTAKING_VERSION } from './undertaking.js';
import { randomToken } from './auth.js';
import { ALL_TESTS, TEST_LABELS } from './scope.js';
import { nowIso, sleep } from './util.js';

// The demo lab runs fixed examples against the deliberately vulnerable demo API, started on a loopback
// port for each run and closed afterwards. Visitors choose an example id and nothing else: no host, URL,
// header or credential ever comes from a request, so the lab cannot be pointed at another system.
const MAX_ACTIVE = 2;
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

export function createLab({ key, log = console }) {
  // In memory on purpose: lab runs are never mixed with real projects, accounts or the data file.
  const store = { data: { projects: {}, scans: {} }, save() {}, saveNow() {} };
  const runs = new Map();

  const forget = (run) => {
    for (const p of run.phases) if (p.scanId) delete store.data.scans[p.scanId];
    delete store.data.projects[run.projectId];
    runs.delete(run.id);
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
    if ([...runs.values()].filter((r) => r.status === 'running').length >= MAX_ACTIVE) {
      return { error: 429, message: 'The demo lab is busy with other runs. Try again in a moment.' };
    }
    const id = randomToken(16);
    const project = buildProject(ex, randomToken(6).replace(/-/g, '_'), key);
    store.data.projects[project.id] = project;
    const run = { id, exampleId: ex.id, title: ex.title, projectId: project.id, status: 'running', createdAt: nowIso(), phases: ex.phases.map((p) => ({ label: p.label })) };
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

  const view = (id) => {
    const run = runs.get(id);
    if (!run) return null;
    const { id: runId, exampleId, title, status, createdAt, finishedAt, error, stopRequested } = run;
    return {
      id: runId, exampleId, title, status, createdAt, finishedAt, error, stopRequested: !!stopRequested,
      phases: run.phases.map((p) => {
        const s = p.scanId && store.data.scans[p.scanId];
        return {
          label: p.label,
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
  };

  return { examples: () => EXAMPLES.map(publicExample), start, view, stop, reportData, shutdown };
}
