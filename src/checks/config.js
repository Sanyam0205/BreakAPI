import { isLoopbackHost } from '../util.js';
import { is2xx, valuesFor, buildRequest, evidence } from './common.js';

const PROBE_ORIGIN = 'https://cors-probe.breakapi.invalid';

export default {
  id: 'config',
  async run({ client, endpoints, accounts, report, project }) {
    const account = accounts[0];
    const ep = endpoints.find((e) => e.method === 'GET' && e.requiresAuth && account) || endpoints.find((e) => e.method === 'GET');
    const req = ep ? buildRequest(ep, valuesFor(ep, account)) : { method: 'GET', path: '/', endpoint: 'GET /' };
    const where = req.endpoint;
    const as = ep?.requiresAuth ? account : undefined;
    const base = await client.send({ ...req, account: as, purpose: 'configuration baseline' });
    if (base.skipped) return;

    const baseUrl = new URL(project.target.baseUrl);
    if (baseUrl.protocol === 'http:') {
      if (!isLoopbackHost(baseUrl.hostname)) {
        report({
          key: 'config|transport-http',
          title: 'API is served over unencrypted HTTP',
          severity: 'high',
          endpoint: baseUrl.origin,
          description: 'The API base URL uses plain HTTP, so tokens, cookies and response data travel unencrypted.',
          impact: 'Anyone on the network path can read or modify traffic, including credentials.',
          remediation: 'Serve the API only over HTTPS (TLS 1.2+), redirect or refuse plain HTTP, and enable HSTS.',
          evidence: [evidence(base)],
        });
      }
    } else if (base.status && !base.headers['strict-transport-security']) {
      report({
        key: 'config|hsts',
        title: 'Strict-Transport-Security header missing',
        severity: 'low',
        endpoint: where,
        description: 'HTTPS responses do not include an HSTS header.',
        impact: 'Clients may be downgraded to HTTP on first contact or via SSL-stripping attacks.',
        remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
        evidence: [evidence(base)],
      });
    }

    // CORS
    const cors = await client.send({ ...req, account: as, headers: { origin: PROBE_ORIGIN }, purpose: 'CORS origin reflection probe' });
    const acao = cors.headers['access-control-allow-origin'];
    const acac = String(cors.headers['access-control-allow-credentials']).toLowerCase() === 'true';
    if (acao === PROBE_ORIGIN) {
      report({
        key: 'config|cors-reflect',
        title: acac ? 'CORS reflects any origin and allows credentials' : 'CORS reflects any origin',
        severity: acac ? 'high' : 'medium',
        endpoint: where,
        description: `A request with Origin: ${PROBE_ORIGIN} was answered with Access-Control-Allow-Origin: ${acao}${acac ? ' and Access-Control-Allow-Credentials: true' : ''}.`,
        impact: acac
          ? 'Any website a logged-in user visits can make authenticated requests to this API and read the responses.'
          : 'Any website can read responses from this API from a visitor’s browser.',
        remediation: 'Replace origin reflection with an explicit allowlist of trusted origins. Never combine a dynamic origin with credentials.',
        evidence: [evidence(cors)],
      });
    } else if (acao === '*' && ep?.requiresAuth) {
      report({
        key: 'config|cors-wildcard',
        title: 'Wildcard CORS on an authenticated endpoint',
        severity: 'low',
        endpoint: where,
        description: 'An endpoint that requires authentication returns Access-Control-Allow-Origin: *.',
        impact: 'Browsers will not send cookies with a wildcard, but header-based tokens held by scripts on other origins can still be used.',
        remediation: 'Restrict CORS to the origins that need it.',
        evidence: [evidence(cors)],
      });
    }
    const nul = await client.send({ ...req, account: as, headers: { origin: 'null' }, purpose: 'CORS null-origin probe' });
    if (nul.headers['access-control-allow-origin'] === 'null') {
      report({
        key: 'config|cors-null',
        title: 'CORS allows the "null" origin',
        severity: 'medium',
        endpoint: where,
        description: 'Access-Control-Allow-Origin: null is returned for Origin: null.',
        impact: 'Sandboxed iframes and local files on any site can send the null origin and read responses.',
        remediation: 'Remove "null" from the allowed origins.',
        evidence: [evidence(nul)],
      });
    }

    // Headers
    const h = base.headers;
    if (h['x-powered-by'] || /\d/.test(h.server || '')) {
      report({
        key: 'config|tech-disclosure',
        title: 'Server technology and version disclosed',
        severity: 'low',
        endpoint: where,
        description: `Response headers reveal the stack: ${[h['x-powered-by'] && `X-Powered-By: ${h['x-powered-by']}`, /\d/.test(h.server || '') && `Server: ${h.server}`].filter(Boolean).join(', ')}.`,
        impact: 'Makes it easier to match the server to known vulnerabilities.',
        remediation: 'Remove X-Powered-By and strip version numbers from the Server header.',
        evidence: [evidence(base)],
      });
    }
    if (base.status && !/nosniff/i.test(h['x-content-type-options'] || '')) {
      report({
        key: 'config|nosniff',
        title: 'X-Content-Type-Options: nosniff missing',
        severity: 'low',
        endpoint: where,
        description: 'Responses do not set X-Content-Type-Options: nosniff.',
        impact: 'Browsers may MIME-sniff responses and interpret data as script or HTML.',
        remediation: 'Add `X-Content-Type-Options: nosniff` to all responses.',
        evidence: [evidence(base)],
      });
    }
    if (ep?.requiresAuth && is2xx(base) && !/no-store|private/i.test(h['cache-control'] || '')) {
      report({
        key: 'config|cache',
        title: 'Authenticated responses may be cached',
        severity: 'low',
        endpoint: where,
        description: 'An authenticated response has no Cache-Control: no-store or private directive.',
        impact: 'Shared caches or proxies could store and serve one user’s data to another.',
        remediation: 'Send `Cache-Control: no-store` on responses containing user data.',
        evidence: [evidence(base)],
      });
    }
  },
};
