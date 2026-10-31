import { label, valuesFor, buildRequest, evidence } from './common.js';
import { cloneBody } from './writes.js';
import { createSynthetic } from '../synthetic.js';

const WRITE_BURST_CAP = 10;

const AUTH_LIKE = /login|signin|sign-in|auth|token|session|otp|password|reset|verify/i;
const LIMIT_HEADER = /^(x-)?ratelimit|^retry-after$/i;

export default {
  id: 'ratelimit',
  async run({ client, endpoints, accounts, report, log, project, scan }) {
    // A write endpoint is only a candidate if a person opted it in; reads always are.
    const usable = endpoints.filter((e) => client.methodAllowed(e.method) && !['HEAD', 'OPTIONS'].includes(e.method) && (e.method === 'GET' || e.syntheticWrites));
    const ep = usable.find((e) => AUTH_LIKE.test(e.path))
      || usable.find((e) => e.method === 'GET' && e.requiresAuth && accounts.length)
      || usable.find((e) => e.method === 'GET');
    if (!ep) return log('Rate-limit check skipped: no eligible endpoint.');

    const { rateLimitBurst, maxRequests, burstRps } = project.controls;
    const writesLeft = ep.method === 'GET' ? Infinity : client.maxWrites - scan.writesSent;
    const n = Math.min(rateLimitBurst, maxRequests - scan.requestsSent, writesLeft, ep.method === 'GET' ? Infinity : WRITE_BURST_CAP);
    if (n < 5) return log('Rate-limit check skipped: not enough request budget left.');

    const account = ep.requiresAuth ? accounts[0] : undefined;
    const req = buildRequest(ep, valuesFor(ep, accounts[0]));
    // A write burst uses a synthetic identity so it can never lock out or flood a real test account.
    if (ep.method !== 'GET') req.body = cloneBody(ep, createSynthetic(scan.id));
    const statuses = {};
    let last;
    for (let i = 0; i < n; i++) {
      const r = await client.sendFor(ep, { ...req, account, burst: true, purpose: `rate-limit burst ${i + 1}/${n}` });
      if (r.skipped) return;
      last = r;
      statuses[r.status] = (statuses[r.status] || 0) + 1;
      const header = Object.keys(r.headers).find((h) => LIMIT_HEADER.test(h));
      if (r.status === 429 || header) {
        return log(`Rate limiting observed on ${label(ep)} after ${i + 1} requests (${r.status === 429 ? 'HTTP 429' : `header ${header}`}).`);
      }
    }

    const sensitive = AUTH_LIKE.test(ep.path);
    report({
      key: `ratelimit|${label(ep)}`,
      title: 'No rate limiting observed',
      severity: sensitive ? 'high' : 'medium',
      confidence: 'medium',
      endpoint: label(ep),
      description: `${n} requests at about ${burstRps}/s produced no HTTP 429 and no rate-limit headers. Status codes: ${Object.entries(statuses).map(([s, c]) => `${s}×${c}`).join(', ')}.`,
      impact: sensitive
        ? 'Credential stuffing and brute-force attacks against authentication are not throttled.'
        : 'Clients can scrape data or exhaust resources without being throttled.',
      remediation: 'Add per-user and per-IP rate limits (stricter on authentication routes), return 429 with Retry-After, and alert on spikes. Limits enforced only above this burst size will not be detected here.',
      evidence: [evidence(last, `Last response of ${n}.`)],
    });
  },
};
