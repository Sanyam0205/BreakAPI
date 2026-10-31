import { similarity } from '../util.js';
import { is2xx, sameKind, label, valuesFor, buildRequest, evidence } from './common.js';

export default {
  id: 'authz',
  async run({ client, endpoints, accounts, report, log }) {
    const usable = endpoints.filter((e) => client.methodAllowed(e.method) && !['HEAD', 'OPTIONS'].includes(e.method));
    const owners = accounts.filter((a) => Object.keys(a.resourceIds || {}).length);
    if (owners.length < 2) log('Cross-account (IDOR/BOLA) checks need at least two test accounts with resource IDs — skipped.');

    // Broken object-level authorization: can account B reach account A's objects?
    for (const ep of usable) {
      const names = ep.params.filter((p) => p.in === 'path').map((p) => p.name);
      if (!names.length || owners.length < 2) continue;
      let flagged = false;
      for (const victim of owners) {
        if (flagged || !names.some((n) => victim.resourceIds[n] != null)) continue;
        const victimReq = buildRequest(ep, valuesFor(ep, victim));
        let baseline;
        for (const attacker of accounts) {
          if (flagged || attacker === victim || attacker.role === 'admin') continue;
          if (names.every((n) => String(attacker.resourceIds?.[n] ?? '') === String(victim.resourceIds[n] ?? ''))) continue;

          if (ep.method !== 'GET') {
            const cross = await client.sendFor(ep, { ...victimReq, account: attacker, purpose: `cross-account write: ${attacker.label} → ${victim.label}'s object` });
            if (is2xx(cross)) {
              flagged = true;
              report({
                key: `authz|bola|${label(ep)}`,
                title: 'Cross-account modification accepted (BOLA/IDOR)',
                severity: 'critical',
                endpoint: label(ep),
                description: `${attacker.label} sent a ${ep.method} to an object owned by ${victim.label} and the API accepted it.`,
                impact: 'Users can modify other users’ data by changing an identifier.',
                remediation: 'Load the object scoped to the caller (e.g. WHERE id = ? AND owner_id = current_user) or check ownership before every write; return 404/403 otherwise.',
                evidence: [evidence(cross)],
              });
            }
            continue;
          }

          baseline ??= await client.send({ ...victimReq, account: victim, purpose: `owner baseline (${victim.label})` });
          if (!is2xx(baseline)) {
            log(`${label(ep)}: owner baseline for ${victim.label} returned ${baseline.status || baseline.skipped}; cross-account test skipped.`);
            break;
          }
          const cross = await client.send({ ...victimReq, account: attacker, purpose: `cross-account read: ${attacker.label} → ${victim.label}'s object` });
          if (!is2xx(cross) || !sameKind(baseline, cross)) continue;
          const control = await client.send({ ...buildRequest(ep, valuesFor(ep, attacker)), account: attacker, purpose: `attacker's own object (${attacker.label})` });
          const simVictim = similarity(cross.body, baseline.body);
          const simOwn = is2xx(control) ? similarity(cross.body, control.body) : 0;
          if (simOwn >= 0.9) continue; // server ignored the ID and returned the caller's own data
          flagged = true;
          const strong = simVictim >= 0.9;
          report({
            key: `authz|bola|${label(ep)}`,
            title: strong ? 'Cross-account data access (BOLA/IDOR)' : 'Possible cross-account data access',
            severity: strong ? 'high' : 'medium',
            confidence: strong ? 'high' : 'low',
            endpoint: label(ep),
            description: `${attacker.label} requested an object owned by ${victim.label} by changing ${names.join(', ')} and received a successful response${strong ? ' matching what the owner sees' : ''}.`,
            impact: 'Any user can read other users’ data by changing an identifier in the request.',
            remediation: 'Authorize every object access against the caller (ownership, tenant or ACL check) on the server. Do not rely on IDs being hard to guess.',
            evidence: [
              evidence(baseline, `Owner (${victim.label}) view.`),
              evidence(cross, `${attacker.label} view of the same object — similarity to owner view ${(simVictim * 100).toFixed(0)}%.`),
            ],
          });
        }
      }
    }

    // Broken function-level authorization: admin-only endpoints reachable by regular users.
    for (const ep of usable.filter((e) => e.adminOnly)) {
      for (const acc of accounts.filter((a) => a.role !== 'admin')) {
        const res = await client.sendFor(ep, { ...buildRequest(ep, valuesFor(ep, acc)), account: acc, purpose: `admin function as ${acc.label}` });
        if (!is2xx(res)) continue;
        report({
          key: `authz|bfla|${label(ep)}`,
          title: 'Admin function accessible to a non-admin account',
          severity: 'high',
          endpoint: label(ep),
          description: `${acc.label} (role: ${acc.role}) received a successful response from an endpoint marked admin-only.`,
          impact: 'Regular users can perform administrative actions or read administrative data.',
          remediation: 'Enforce role checks server-side on every admin route (deny by default), ideally in shared middleware.',
          evidence: [evidence(res)],
        });
        break;
      }
    }

    // Enumerable identifiers (informational).
    const numeric = new Set();
    for (const a of owners) {
      for (const [k, v] of Object.entries(a.resourceIds)) if (/^\d{1,9}$/.test(String(v))) numeric.add(k);
    }
    for (const name of numeric) {
      if (!usable.some((e) => e.params.some((p) => p.in === 'path' && p.name === name))) continue;
      report({
        key: `authz|sequential|${name}`,
        title: `Sequential numeric identifiers ("${name}")`,
        severity: 'info',
        endpoint: `parameter: ${name}`,
        description: 'Test account resources use small integer IDs.',
        impact: 'Not a vulnerability on its own, but makes enumeration trivial if any authorization check is missing.',
        remediation: 'Keep strict ownership checks; consider UUIDs for externally visible identifiers.',
        evidence: [],
      });
    }
  },
};
