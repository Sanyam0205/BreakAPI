import { isLoopbackHost } from './util.js';
import { UNDERTAKING_VERSION, hashUndertaking } from './undertaking.js';
import { getConfig } from './config.js';
import { hostRefusal } from './netguard.js';

export const ALL_TESTS = ['config', 'exposure', 'authn', 'authz', 'input', 'validation', 'identity', 'logic', 'ratelimit'];

export const TEST_LABELS = {
  config: 'Configuration (transport, CORS, headers)',
  exposure: 'Exposed files & diagnostics',
  authn: 'Authentication',
  authz: 'Authorization & cross-account access',
  input: 'Input handling (non-destructive probes)',
  validation: 'Data validation (synthetic writes: emails, types, ranges)',
  identity: 'Identity & accounts (signup, verification, enumeration)',
  logic: 'Business logic (quantities, prices, replays)',
  ratelimit: 'Rate limiting (bounded burst)',
};

/** Tests that send mutated payloads and so also need the global write switch and per-endpoint opt-in. */
export const WRITE_TESTS = ['validation', 'identity', 'logic'];

/** Ceilings that apply whatever the stored controls say. Enforced again in GuardedClient. */
export const HARD_LIMITS = {
  maxRequests: 20000,
  rps: 50,
  burstRps: 100,
  maxWrites: 500,
  maxDurationMs: 2 * 3600_000,
};

export const VERIFY_TTL_MS = 24 * 3600_000;

/** The allowed-hosts entry that covers this URL, or undefined. Exact host[:port] or bare hostname; no wildcards. */
export function matchingHost(authorization, url) {
  const u = new URL(url);
  return (authorization?.allowedHosts || []).find((entry) => {
    const h = String(entry).trim().toLowerCase();
    return h === u.host.toLowerCase() || h === u.hostname.toLowerCase();
  });
}

export const hostAllowed = (authorization, url) => !!matchingHost(authorization, url);

/**
 * The network rules a project's requests run under. A lab project is built by the server around a
 * loopback demo API it started itself (src/lab.js); no request can set this flag or choose that host.
 */
export function targetConfig(project) {
  // A playground project scans the separately hosted simulation, so it gets no loopback exemption.
  return project?.lab && !project.simHost ? { ...getConfig(), allowLocalTargets: true } : getConfig();
}

/**
 * The simulation host of a lab playground project. It is copied from server configuration
 * (BREAKAPI_SIM_URL) when the lab builds the project in memory. Real projects never carry it, and no
 * request can set it, so this is not a way around ownership proof for anything a visitor chooses.
 */
export function isSimEntry(project, entry) {
  return !!(project?.lab && project.simHost && String(entry).toLowerCase() === String(project.simHost).toLowerCase());
}

/** Local hosts skip the verification challenge, but only where local targets are allowed at all. */
export function isLocalEntry(entry, project) {
  if (!targetConfig(project).allowLocalTargets) return false;
  try {
    return isLoopbackHost(new URL(`http://${entry}`).hostname);
  } catch {
    return false;
  }
}

export function needsVerification(baseUrl) {
  return !isLoopbackHost(new URL(baseUrl).hostname);
}

/** Verification only counts for the authorization it was made under, and only while fresh. */
export function entryVerified(project, entry, at = new Date()) {
  if (isSimEntry(project, entry)) return true;
  const a = project.authorization;
  return (project.verifiedHosts || []).some((v) => v.host === String(entry).toLowerCase()
    && v.authorizationId === a?.id
    && at - new Date(v.at) < VERIFY_TTL_MS);
}

/** Per-host status for the UI, pre-flight and reports. */
export function hostStatus(project, at = new Date()) {
  return (project.authorization?.allowedHosts || []).map((host) => {
    const local = isLocalEntry(host, project);
    const refused = hostRefusal(host, targetConfig(project));
    const v = (project.verifiedHosts || []).find((x) => x.host === host.toLowerCase() && x.authorizationId === project.authorization.id);
    if (refused) return { host, local: false, refused, verified: false, method: 'refused by server policy', at: null, stale: false };
    const sim = isSimEntry(project, host);
    return {
      host,
      local,
      verified: local || entryVerified(project, host, at),
      method: local ? 'local development only (no ownership proof)' : sim ? 'breakAPI simulation, configured by the server operator' : v?.method,
      at: v?.at,
      stale: !local && !!v && !entryVerified(project, host, at),
    };
  });
}

/** An authorization recorded for someone else stays pending until that person confirms it by email. */
export function authorizationConfirmed(a) {
  return !!a?.confirmedAt;
}

export function undertakingCurrent(a) {
  return a?.undertaking?.version === UNDERTAKING_VERSION && a.undertaking.sha256 === hashUndertaking();
}

/** Every reason a scan must not start right now. Empty array = clear to run. */
export function preflight(project, at = new Date()) {
  const problems = [];
  const a = project.authorization;
  const t = project.target || {};
  const c = project.controls || {};

  if (!a) return ['No authorization has been recorded. Complete the Authorization step.'];
  if (a.revokedAt) problems.push(`Authorization was revoked at ${a.revokedAt}. Record a new authorization to continue.`);
  if (!a.attestations?.ownsOrAuthorized || !a.attestations?.scopeAccurate || !a.attestations?.acceptsImpact) {
    problems.push('All authorization attestations must be confirmed.');
  }
  if (!authorizationConfirmed(a) && !a.revokedAt) problems.push(`Waiting for ${a.authorizerEmail} to confirm this authorization from the link emailed to them.`);
  else if (!undertakingCurrent(a)) problems.push('The testing undertaking has not been accepted (or its wording changed). Record the authorization again and accept it.');
  if (new Date(a.expiresAt) <= at) problems.push(`Authorization expired at ${a.expiresAt}.`);
  if (!(a.allowedTests || []).length) problems.push('No test categories are authorized.');

  if (!t.baseUrl) {
    problems.push('No base URL configured.');
  } else if (!hostAllowed(a, t.baseUrl)) {
    problems.push(`Base URL host "${new URL(t.baseUrl).host}" is not in the authorized scope.`);
  }
  for (const h of hostStatus(project, at)) {
    if (h.refused) {
      problems.push(`"${h.host}" cannot be tested from this server: ${h.refused}`);
      continue;
    }
    if (h.verified) continue;
    problems.push(`Control of "${h.host}" is not verified${h.stale ? ' (the last verification is older than 24 hours)' : ''}. Publish the verification token, then check it.`);
  }
  if (!(t.endpoints || []).some((e) => e.enabled)) problems.push('No endpoints are enabled for testing.');

  if (c.windowStart && new Date(c.windowStart) > at) problems.push(`Test window has not started (opens ${c.windowStart}).`);
  if (c.windowEnd && new Date(c.windowEnd) <= at) problems.push(`Test window closed at ${c.windowEnd}.`);
  return problems;
}
