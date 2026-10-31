import { is2xx, evidence, label } from './common.js';
import { syntheticTargets, actingAccount, ownRequest, cloneBody, parseJson, findKey, acceptance, accepted, confidenceOf } from './writes.js';
import { createSynthetic, isEmailField, isNumericField } from '../synthetic.js';

const MONEY = /(quantity|qty|amount|price|total|discount)/i; // handled by the logic check
const PRIVILEGED = { role: 'admin', isAdmin: true, email_verified: true };

export default {
  id: 'validation',
  async run({ client, endpoints, accounts, report, log, scan }) {
    const syn = createSynthetic(scan.id);
    const targets = syntheticTargets(client, endpoints).filter((e) => e.kind !== 'login' && e.bodyExample && typeof e.bodyExample === 'object');
    if (!targets.length) return log('Validation checks skipped: no endpoint with a request body is opted in to synthetic writes (and write requests authorized).');

    for (const ep of targets) {
      const account = actingAccount(ep, accounts);
      if (ep.requiresAuth && !account) { log(`${label(ep)}: needs a regular test account; validation skipped.`); continue; }
      const req = ownRequest(ep, account);
      if (!req) { log(`${label(ep)}: path parameters need resource IDs on the test account; validation skipped.`); continue; }
      const send = (body, purpose) => client.sendSynthetic(ep, { ...req, body, account, purpose });
      const where = label(ep);

      const base = await send(cloneBody(ep, syn), 'validation baseline (synthetic data)');
      if (base.skipped) continue;
      if (!is2xx(base)) { log(`${where}: the baseline synthetic request returned ${base.status}; validation skipped (the example body is rejected).`); continue; }
      const baseJson = parseJson(base);
      const fields = Object.keys(ep.bodyExample);

      // Malformed email addresses should be rejected by the server, whatever the client form does.
      for (const f of fields.filter(isEmailField)) {
        for (const bad of syn.malformedEmails) {
          const r = await send(cloneBody(ep, syn, { [f]: bad }), `malformed email → ${f}`);
          if (r.skipped) break;
          const acc = acceptance(r, f, bad);
          if (!accepted(acc)) continue;
          report({
            key: `validation|email|${where}|${f}`,
            title: 'Malformed email address accepted',
            severity: 'medium',
            confidence: confidenceOf(acc),
            endpoint: where,
            param: f,
            description: `The server accepted "${bad}" as the "${f}" value and returned HTTP ${r.status}. Validation appears to happen only in the client, if at all.`,
            impact: 'Accounts or records can be created with undeliverable or deliberately malformed addresses, which breaks verification, password reset and notifications, and can hide abuse.',
            remediation: 'Validate email syntax on the server (a maintained validator or a strict pattern), normalize it, and return 400 for anything else.',
            evidence: [evidence(r, `Synthetic value "${bad}". Valid synthetic requests to the same endpoint returned ${base.status}.`)],
          });
          break;
        }
      }

      // Wrong types and implausible values for numeric fields.
      for (const f of fields.filter((k) => isNumericField(k) && typeof ep.bodyExample[k] === 'number')) {
        const wrong = await send(cloneBody(ep, syn, { [f]: 'breakapi-not-a-number' }), `type confusion → ${f}`);
        if (wrong.skipped) break;
        const wrongAcc = acceptance(wrong, f, 'breakapi-not-a-number');
        if (accepted(wrongAcc)) {
          report({
            key: `validation|type|${where}|${f}`,
            title: `Text accepted for numeric field "${f}"`,
            severity: 'low',
            confidence: confidenceOf(wrongAcc, 'medium'),
            endpoint: where,
            param: f,
            description: `A string was accepted for "${f}" and returned HTTP ${wrong.status}.`,
            impact: 'Loose typing hides bugs and can let unexpected values reach calculations, storage or downstream services.',
            remediation: 'Validate the request body against a schema (types, ranges, required fields) and reject mismatches with 400.',
            evidence: [evidence(wrong)],
          });
        }
        if (MONEY.test(f)) continue;
        for (const value of [-1, 999999999999]) {
          const r = await send(cloneBody(ep, syn, { [f]: value }), `implausible value ${value} → ${f}`);
          if (r.skipped) break;
          const acc = acceptance(r, f, value);
          if (!accepted(acc)) continue;
          report({
            key: `validation|range|${where}|${f}`,
            title: `Implausible value accepted for "${f}"`,
            severity: 'low',
            confidence: confidenceOf(acc, 'medium'),
            endpoint: where,
            param: f,
            description: `${value} was accepted for "${f}" and returned HTTP ${r.status}.`,
            impact: 'Records can hold impossible data (for example a negative age), which skews reports, limits and business rules.',
            remediation: 'Enforce minimum and maximum bounds on the server for every numeric field.',
            evidence: [evidence(r, 'Indicator: whether this value is actually implausible depends on what the field means.')],
          });
          break;
        }
      }

      // Mass assignment: privileged fields the client never sends must not be settable.
      const extra = Object.fromEntries(Object.entries(PRIVILEGED).filter(([k]) => !(k in ep.bodyExample)));
      const mass = await send(cloneBody(ep, syn, extra), 'mass assignment (privileged fields)');
      if (mass.skipped || !is2xx(mass)) continue;
      const massJson = parseJson(mass);
      const set = Object.entries(extra).filter(([k, v]) => {
        const got = findKey(massJson, [k]);
        const was = findKey(baseJson, [k]);
        return got && String(got.value) === String(v) && !(was && String(was.value) === String(v));
      }).map(([k]) => k);
      if (set.length) {
        report({
          key: `validation|mass-assignment|${where}`,
          title: 'Privileged fields can be set by the client (mass assignment)',
          severity: 'high',
          endpoint: where,
          description: `Extra fields ${set.map((k) => `"${k}"`).join(', ')} were sent and came back set to the supplied values.`,
          impact: 'A user can grant themselves administrator rights or mark their own account as verified.',
          remediation: 'Bind request bodies to an explicit allowlist of writable fields. Set role and verification state only on the server.',
          evidence: [evidence(mass, 'Synthetic account data only.')],
        });
      }
    }
  },
};
