import { is2xx, evidence } from './common.js';

// Read-only GETs for well-known files and diagnostic endpoints, each confirmed by a content signature.
const PROBES = [
  { path: '/.env', severity: 'high', title: 'Environment file publicly accessible', sig: /^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m },
  { path: '/.git/config', severity: 'high', title: 'Git repository metadata exposed', sig: /\[core\]|repositoryformatversion/ },
  { path: '/.git/HEAD', severity: 'high', title: 'Git repository metadata exposed', sig: /^ref: refs\//m },
  { path: '/actuator/env', severity: 'high', title: 'Spring Boot actuator environment exposed', sig: /"propertySources"|"activeProfiles"/ },
  { path: '/actuator', severity: 'medium', title: 'Spring Boot actuator index exposed', sig: /"_links"\s*:/ },
  { path: '/debug/vars', severity: 'medium', title: 'Go expvar debug endpoint exposed', sig: /"memstats"|"cmdline"/ },
  { path: '/debug/pprof/', severity: 'medium', title: 'Go pprof profiling endpoint exposed', sig: /Types of profiles available/ },
  { path: '/server-status', severity: 'medium', title: 'Apache server-status page exposed', sig: /Apache Server Status/ },
  { path: '/phpinfo.php', severity: 'medium', title: 'phpinfo() page exposed', sig: /phpinfo\(\)|PHP Version/ },
  { path: '/config.json', severity: 'medium', title: 'Configuration file with secrets exposed', sig: /"(password|secret|apiKey|api_key|token|privateKey)"\s*:/i },
  { path: '/.DS_Store', severity: 'low', title: '.DS_Store file exposed', sig: /Bud1/ },
  { path: '/openapi.json', severity: 'info', title: 'API specification is publicly accessible', sig: /"openapi"\s*:|"swagger"\s*:/ },
  { path: '/swagger.json', severity: 'info', title: 'API specification is publicly accessible', sig: /"openapi"\s*:|"swagger"\s*:/ },
];

const REMEDIATION = {
  high: 'Remove the file from the web root or block it at the server/proxy, then rotate any secrets it contained.',
  medium: 'Disable the endpoint in production or restrict it to an internal network/admin authentication.',
  low: 'Remove the file from the deployed artifact and block dotfiles at the server.',
  info: 'Confirm that publishing the specification is intended; if not, restrict access to it.',
};

export default {
  id: 'exposure',
  async run({ client, report, project }) {
    const basePath = new URL(project.target.baseUrl).pathname.replace(/\/$/, '');
    const roots = [...new Set(['', basePath])];
    const reported = new Set();
    for (const root of roots) {
      for (const probe of PROBES) {
        if (reported.has(probe.title)) continue;
        const res = await client.send({ method: 'GET', path: root + probe.path, fromOrigin: true, purpose: `exposure probe ${probe.path}` });
        if (!is2xx(res) || !probe.sig.test(res.body)) continue;
        reported.add(probe.title);
        report({
          key: `exposure|${root}${probe.path}`,
          title: probe.title,
          severity: probe.severity,
          endpoint: `GET ${root}${probe.path}`,
          description: `${root}${probe.path} is reachable without authentication and its content matches a known signature.`,
          impact: probe.severity === 'info'
            ? 'Attackers get a complete map of the API surface.'
            : 'May leak credentials, source code, infrastructure details or runtime internals.',
          remediation: REMEDIATION[probe.severity],
          evidence: [evidence(res)],
        });
      }
    }
  },
};
