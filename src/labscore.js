// Ground truth for lab playground runs: what the sandbox had planted vs. what breakAPI reported.
// The catalog (ids, test categories, detection signatures) comes from the simulation backend.

export class LabConfigError extends Error {}

/** `{ preset }` or `{ vulns: [ids] }` → sorted known ids. Unknown ids are an error, never ignored. */
export function resolvePlayground(catalog, input = {}) {
  const known = new Set(catalog.vulns.map((v) => v.id));
  let ids;
  if (input.preset !== undefined && input.preset !== null && input.preset !== '') {
    const preset = catalog.presets.find((p) => p.id === input.preset);
    if (!preset) throw new LabConfigError('There is no preset with that id.');
    ids = preset.vulns;
  } else if (Array.isArray(input.vulns)) {
    if (input.vulns.length > known.size) throw new LabConfigError('Too many vulnerabilities listed.');
    ids = input.vulns;
  } else {
    throw new LabConfigError('Choose a preset or a list of vulnerabilities.');
  }
  for (const id of ids) if (typeof id !== 'string' || !known.has(id)) throw new LabConfigError('One of the vulnerabilities is not in the catalog.');
  return [...new Set(ids)].sort();
}

/** Every test category the catalog covers. A playground scan always runs all of them, so false alarms show. */
export const catalogTests = (catalog) => [...new Set(catalog.vulns.map((v) => v.test))];

const matches = (finding, d) => finding.title === d.title && (!d.endpoint || finding.endpoint === d.endpoint);

/**
 * One row per catalog entry in the tested categories: hit (planted, found), miss (planted, not found),
 * false-alarm (patched, found anyway) or clean. Findings that match no entry are listed separately.
 */
export function scoreRun(catalog, { planted, findings, tests }) {
  const on = new Set(planted);
  const rows = catalog.vulns.filter((v) => !tests || tests.includes(v.test)).map((v) => {
    const hits = findings.filter((f) => (v.detects || []).some((d) => matches(f, d)));
    const isPlanted = on.has(v.id);
    const detected = hits.length > 0;
    return {
      id: v.id,
      test: v.test,
      title: v.title,
      severity: v.severity,
      planted: isPlanted,
      detected,
      outcome: isPlanted ? (detected ? 'hit' : 'miss') : (detected ? 'false-alarm' : 'clean'),
      findings: hits.map((f) => f.id ?? f.key),
    };
  });
  const explained = new Set(rows.flatMap((r) => r.findings));
  const plantedRows = rows.filter((r) => r.planted);
  return {
    catalogVersion: catalog.version,
    rows,
    unexplained: findings.filter((f) => !explained.has(f.id ?? f.key)).map((f) => ({ id: f.id, title: f.title, endpoint: f.endpoint, severity: f.severity })),
    planted: plantedRows.length,
    hits: plantedRows.filter((r) => r.detected).length,
    falseAlarms: rows.filter((r) => r.outcome === 'false-alarm').length,
    recall: plantedRows.length ? plantedRows.filter((r) => r.detected).length / plantedRows.length : null,
  };
}
