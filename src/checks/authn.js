import { createHmac } from 'node:crypto';
import { mask } from '../util.js';
import { is2xx, sameKind, label, valuesFor, buildRequest, evidence } from './common.js';

const INVALID_CREDENTIAL = 'breakapi-invalid-credential';

// Checked offline against the supplied test token only; no requests are made for this.
const WEAK_SECRETS = [
  'secret', 'password', 'changeme', 'change-me', '123456', '12345678', 'qwerty', 'admin', 'test', 'key',
  'jwt', 'jwtsecret', 'jwt_secret', 'jwt-secret', 'secretkey', 'secret_key', 'secret-key', 'supersecret',
  'mysecret', 'my-secret', 'your-256-bit-secret', 'your_jwt_secret', 'default', 'development', 'dev',
  'token', 'shhhhh', 'keyboard cat', 's3cr3t', 'letmein',
];

const b64json = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

function decodeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  try {
    return { header: b64json(parts[0]), payload: b64json(parts[1]), parts };
  } catch {
    return null;
  }
}

export default {
  id: 'authn',
  async run({ client, endpoints, accounts, report }) {
    const targets = endpoints.filter((e) => e.requiresAuth && client.methodAllowed(e.method) && e.method !== 'OPTIONS');
    const primary = accounts[0];

    for (const ep of targets) {
      const req = buildRequest(ep, valuesFor(ep, primary));
      const baseline = primary ? await client.sendFor(ep, { ...req, account: primary, purpose: 'authentication baseline' }) : null;
      const anon = await client.sendFor(ep, { ...req, purpose: 'request without credentials' });
      if (is2xx(anon) && sameKind(baseline, anon)) {
        report({
          key: `authn|anonymous|${label(ep)}`,
          title: 'Endpoint accessible without authentication',
          severity: 'high',
          confidence: baseline && is2xx(baseline) ? 'high' : 'medium',
          endpoint: label(ep),
          description: 'This endpoint is declared as requiring authentication, but it returned a successful response to a request with no credentials.',
          impact: 'Anyone on the internet can call it and read or change whatever it exposes.',
          remediation: 'Enforce authentication in middleware that runs before the handler (deny by default), and add a test that calls the endpoint anonymously and expects 401.',
          evidence: [evidence(anon, 'No Authorization header, cookie or API key was sent.')],
        });
        continue;
      }
      if (primary && is2xx(baseline)) {
        const bad = await client.sendFor(ep, { ...req, account: primary, authOverride: INVALID_CREDENTIAL, purpose: 'invalid credential' });
        if (is2xx(bad) && sameKind(baseline, bad)) {
          report({
            key: `authn|invalid-credential|${label(ep)}`,
            title: 'Invalid credentials are accepted',
            severity: 'high',
            endpoint: label(ep),
            description: `A request carrying a made-up credential ("${INVALID_CREDENTIAL}") succeeded.`,
            impact: 'Authentication only checks that a credential is present, not that it is valid.',
            remediation: 'Validate every credential (signature, expiry, revocation) and reject anything that does not verify.',
            evidence: [evidence(bad)],
          });
        }
      }
    }

    // JWT checks on supplied test tokens.
    const probeEp = targets.find((e) => e.method === 'GET');
    let forgeryTested = false;
    for (const acc of accounts.filter((a) => a.authType !== 'cookie')) {
      const jwt = decodeJwt(acc.secret);
      if (!jwt) continue;
      const { header, payload, parts } = jwt;

      if (!payload.exp) {
        report({
          key: `authn|jwt-no-exp|${acc.label}`,
          title: 'JWT has no expiry',
          severity: 'medium',
          endpoint: `credential: ${acc.label}`,
          description: 'The test account’s token has no "exp" claim.',
          impact: 'A leaked token stays valid forever unless the signing key is rotated.',
          remediation: 'Issue short-lived access tokens (minutes to hours) with an "exp" claim and use refresh tokens for longer sessions.',
          evidence: [{ note: `Token header: ${JSON.stringify(header)}; claims present: ${Object.keys(payload).join(', ')}` }],
        });
      } else if (payload.iat && payload.exp - payload.iat > 30 * 86400) {
        report({
          key: `authn|jwt-long-lived|${acc.label}`,
          title: 'JWT lifetime is longer than 30 days',
          severity: 'low',
          endpoint: `credential: ${acc.label}`,
          description: `The token is valid for ${Math.round((payload.exp - payload.iat) / 86400)} days.`,
          impact: 'Long-lived tokens widen the window for misuse after a leak.',
          remediation: 'Shorten access-token lifetime and rely on refresh tokens.',
          evidence: [{ note: `iat=${payload.iat}, exp=${payload.exp}` }],
        });
      }

      const hash = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }[header.alg];
      if (hash) {
        const found = WEAK_SECRETS.find((s) => createHmac(hash, s).update(`${parts[0]}.${parts[1]}`).digest('base64url') === parts[2]);
        if (found) {
          report({
            key: 'authn|jwt-weak-secret',
            title: 'JWT is signed with a guessable secret',
            severity: 'critical',
            endpoint: `credential: ${acc.label}`,
            description: `The token’s ${header.alg} signature verifies with a common wordlist secret (${mask(found)}). This was checked offline.`,
            impact: 'Anyone can forge tokens for any user or role.',
            remediation: 'Rotate the signing key to a random 256-bit secret from a secrets manager (or switch to asymmetric keys) and invalidate existing tokens.',
            evidence: [{ note: 'Matched an entry in breakAPI’s built-in weak-secret list. No requests were sent for this check.' }],
          });
        }
      }

      // Online forgery tests are about the server, not the account: one proof is enough.
      if (!probeEp || forgeryTested) continue;
      const req = buildRequest(probeEp, valuesFor(probeEp, acc));
      const good = await client.send({ ...req, account: acc, purpose: 'JWT baseline' });
      if (!is2xx(good)) continue;
      const anon = await client.send({ ...req, purpose: 'JWT control (no credentials)' });
      if (is2xx(anon)) continue;
      forgeryTested = true;

      const noneToken = `${Buffer.from(JSON.stringify({ ...header, alg: 'none' })).toString('base64url')}.${parts[1]}.`;
      const none = await client.send({ ...req, account: acc, authOverride: noneToken, purpose: 'JWT alg=none' });
      if (is2xx(none)) {
        report({
          key: 'authn|jwt-alg-none',
          title: 'JWT with alg "none" is accepted',
          severity: 'critical',
          endpoint: label(probeEp),
          description: 'The test token was re-encoded with alg "none" and no signature, and the API accepted it.',
          impact: 'Anyone can forge a token for any user, including administrators.',
          remediation: 'Pin the expected algorithm when verifying (e.g. algorithms: ["HS256"]) and reject unsigned tokens.',
          evidence: [evidence(none)],
        });
        continue;
      }
      const sig = parts[2];
      const tamperedToken = `${parts[0]}.${parts[1]}.${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}`;
      const tampered = await client.send({ ...req, account: acc, authOverride: tamperedToken, purpose: 'JWT tampered signature' });
      if (is2xx(tampered)) {
        report({
          key: 'authn|jwt-signature',
          title: 'JWT signature is not verified',
          severity: 'critical',
          endpoint: label(probeEp),
          description: 'A token with a corrupted signature was accepted.',
          impact: 'Token claims can be edited freely; anyone can impersonate any user.',
          remediation: 'Verify the signature with a maintained JWT library (use verify, not decode).',
          evidence: [evidence(tampered)],
        });
      }
    }
  },
};
