import { randomBytes } from 'node:crypto';
import { label, valuesFor, buildRequest, evidence } from './common.js';

const SQL_ERRORS = /SQL syntax|SQLITE_ERROR|SQLSTATE\[|syntax error at or near|unterminated quoted string|ORA-\d{5}|Microsoft OLE DB|ODBC SQL Server Driver|PG::SyntaxError|Unclosed quotation mark|quoted string not properly terminated|sqlite3\.OperationalError|MySqlException|near "[^"]*": syntax error/i;
const PASSWD = /root:[^:\n]*:0:0:/;
const MAX_ENDPOINTS = 40;

// Probes are read-only GETs with harmless values: a stray quote, an inert marker tag,
// a traversal path and a non-numeric string. Nothing here writes or deletes data.
export default {
  id: 'input',
  async run({ client, endpoints, accounts, report }) {
    const acc = accounts[0];
    const targets = endpoints.filter((e) => e.method === 'GET' && e.params.length).slice(0, MAX_ENDPOINTS);

    for (const ep of targets) {
      const account = ep.requiresAuth ? acc : undefined;
      const base = valuesFor(ep, acc);
      const baseline = await client.send({ ...buildRequest(ep, base), account, purpose: 'input baseline' });
      if (baseline.skipped) continue;

      for (const p of ep.params) {
        const original = base[p.name] ?? (p.type === 'integer' ? '1' : 'test');
        const probe = (value, purpose) => client.send({ ...buildRequest(ep, { ...base, [p.name]: value }), account, purpose: `${purpose} → ${p.name}` });
        const where = `${p.in} parameter "${p.name}"`;

        const sq = await probe(`${original}'"`, 'SQL error probe');
        if (SQL_ERRORS.test(sq.body) && !SQL_ERRORS.test(baseline.body)) {
          report({
            key: `input|sqli|${label(ep)}|${p.name}`,
            title: 'Possible SQL injection (database error on quote)',
            severity: 'high',
            confidence: 'medium',
            endpoint: label(ep),
            param: p.name,
            description: `Adding a quote to the ${where} produced a database syntax error, which suggests the value is concatenated into a SQL query.`,
            impact: 'If confirmed, an attacker could read or modify database contents.',
            remediation: 'Use parameterized queries / prepared statements or a query builder for every value; never build SQL with string concatenation. Hide database errors from clients.',
            evidence: [evidence(sq)],
          });
        }

        const marker = `bp${randomBytes(3).toString('hex')}`;
        const rf = await probe(`${marker}<${marker}>`, 'reflection probe');
        if (/html/i.test(rf.contentType) && rf.body.includes(`<${marker}>`)) {
          report({
            key: `input|reflected|${label(ep)}|${p.name}`,
            title: 'Input reflected into HTML without encoding (XSS risk)',
            severity: 'medium',
            endpoint: label(ep),
            param: p.name,
            description: `The ${where} is echoed into an HTML response without escaping; an inert marker tag <${marker}> came back intact.`,
            impact: 'Attackers can craft links that run script in a victim’s browser on this origin.',
            remediation: 'HTML-encode output (use a templating engine with auto-escaping), return JSON with a JSON content type for API responses, and add a Content-Security-Policy.',
            evidence: [evidence(rf)],
          });
        }

        if (p.in === 'path') {
          const tr = await probe('../../../../../../etc/passwd', 'path traversal probe');
          if (PASSWD.test(tr.body)) {
            report({
              key: `input|traversal|${label(ep)}|${p.name}`,
              title: 'Path traversal reads server files',
              severity: 'critical',
              endpoint: label(ep),
              param: p.name,
              description: `A ../ sequence in the ${where} returned the contents of /etc/passwd.`,
              impact: 'Attackers can read arbitrary files, including configuration and secrets.',
              remediation: 'Never build filesystem paths from user input; map IDs to files server-side, or resolve and verify the path stays inside an allowed directory.',
              evidence: [evidence(tr)],
            });
          }
        }

        if (p.type === 'integer' || p.type === 'number' || /^\d+$/.test(original)) {
          const ty = await probe('breakapi-not-a-number', 'type validation probe');
          if (ty.status >= 500 && !(baseline.status >= 500)) {
            report({
              key: `input|type|${label(ep)}|${p.name}`,
              title: 'Unvalidated input causes a server error',
              severity: 'low',
              endpoint: label(ep),
              param: p.name,
              description: `A non-numeric value for the numeric ${where} caused HTTP ${ty.status}.`,
              impact: 'Missing validation can hide deeper bugs and leak error details.',
              remediation: 'Validate request parameters against a schema and return 400 for invalid input.',
              evidence: [evidence(ty)],
            });
          }
        }
      }
    }
  },
};
