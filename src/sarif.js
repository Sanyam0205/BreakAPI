import { VERSION } from './version.js';
import { LIMITATIONS } from './report.js';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
// GitHub code scanning ranks by this 0-10 number.
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.0', low: '2.5', info: '0.5' };

/** One rule per kind of finding: the first two parts of its key, e.g. `authz|bola|GET /x` -> `authz/bola`. */
const ruleIdOf = (f) => String(f.key || f.check || 'finding').split('|').slice(0, 2).join('/');

/**
 * A SARIF 2.1.0 log for one scan. Findings are about HTTP endpoints, not source files, so locations
 * are logical (the endpoint). Evidence bodies are left out: the JSON report carries them.
 * Absence of results is not a statement that the API is secure (see run.properties.limitations).
 */
export function toSarif(project, scan) {
  const rules = new Map();
  for (const f of scan.findings) {
    const id = ruleIdOf(f);
    if (rules.has(id)) continue;
    rules.set(id, {
      id,
      name: id,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description || f.title },
      help: { text: f.remediation || 'See the breakAPI report for the fix.' },
      defaultConfiguration: { level: LEVEL[f.severity] || 'warning' },
      properties: { 'security-severity': SECURITY_SEVERITY[f.severity] || '5.0', tags: ['security', 'api', f.check].filter(Boolean) },
    });
  }
  const a = scan.authorizationSnapshot || {};
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'breakAPI', version: VERSION, rules: [...rules.values()] } },
      invocations: [{
        executionSuccessful: scan.status === 'completed',
        startTimeUtc: scan.startedAt,
        endTimeUtc: scan.finishedAt,
        properties: { status: scan.status, stopReason: scan.stopReason, checks: scan.checks },
      }],
      results: scan.findings.map((f) => ({
        ruleId: ruleIdOf(f),
        level: LEVEL[f.severity] || 'warning',
        message: { text: `${f.title}. ${f.description || ''} Impact: ${f.impact || 'n/a'} Fix: ${f.remediation || 'n/a'}`.trim() },
        locations: [{ logicalLocations: [{ name: f.endpoint, kind: 'resource' }] }],
        partialFingerprints: { 'breakapi/key': f.key },
        properties: { severity: f.severity, confidence: f.confidence, check: f.check, parameter: f.param },
      })),
      properties: {
        project: project.name,
        scanId: scan.id,
        authorization: { authorizer: a.authorizerName, expiresAt: a.expiresAt, hosts: a.allowedHosts },
        limitations: LIMITATIONS,
      },
    }],
  };
}
