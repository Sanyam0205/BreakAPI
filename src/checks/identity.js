import { is2xx, evidence, label, valuesFor, buildRequest } from './common.js';
import { syntheticTargets, actingAccount, ownRequest, cloneBody, parseJson, findKey } from './writes.js';
import { createSynthetic, isEmailField, isPasswordField } from '../synthetic.js';
import { similarity } from '../util.js';

const TOKEN_KEYS = ['token', 'access_token', 'accessToken', 'jwt', 'session', 'sessionToken'];
const VERIFIED_KEYS = ['email_verified', 'emailVerified', 'verified', 'isVerified', 'is_verified'];

const stripEmails = (s, ...emails) => emails.reduce((t, e) => t.split(e).join('<email>'), String(s));

export default {
  id: 'identity',
  async run({ client, endpoints, accounts, report, log, scan }) {
    const syn = createSynthetic(scan.id);
    const signups = syntheticTargets(client, endpoints, ['signup']);
    const logins = syntheticTargets(client, endpoints, ['login']);
    if (!signups.length && !logins.length) return log('Identity checks skipped: no signup or login endpoint is opted in to synthetic writes (and write requests authorized).');

    for (const ep of signups) {
      const account = actingAccount(ep, accounts);
      const req = ownRequest(ep, account);
      if (!req || (ep.requiresAuth && !account)) { log(`${label(ep)}: cannot build a safe request; identity checks skipped.`); continue; }
      const where = label(ep);
      const emailField = Object.keys(ep.bodyExample || {}).find(isEmailField);
      const passwordField = Object.keys(ep.bodyExample || {}).find(isPasswordField);
      const send = (body, purpose) => client.sendSynthetic(ep, { ...req, body, account, purpose });

      const body = cloneBody(ep, syn);
      const created = await send(body, 'signup with a synthetic identity');
      if (created.skipped || !is2xx(created)) {
        if (!created.skipped) log(`${where}: signup with synthetic data returned ${created.status}; identity checks skipped.`);
        continue;
      }
      const json = parseJson(created);
      const token = findKey(json, TOKEN_KEYS);
      const verified = findKey(json, VERIFIED_KEYS);

      // A session issued before the email is verified.
      if (token && typeof token.value === 'string') {
        const probe = endpoints.find((e) => e.method === 'GET' && e.requiresAuth && !e.params.some((p) => p.in === 'path'));
        const newAcct = { label: 'new synthetic account', authType: 'bearer', secret: token.value };
        const used = probe ? await client.send({ ...buildRequest(probe, valuesFor(probe, null)), account: newAcct, purpose: 'use the new account before verification' }) : null;
        if (used && is2xx(used) && verified?.value === false) {
          report({
            key: `identity|unverified-access|${where}`,
            title: 'New account has full access before its email is verified',
            severity: 'high',
            endpoint: where,
            description: `Signup returned a working session token while "${verified.key}" is false; the token was accepted by ${label(probe)}.`,
            impact: 'Anyone can create accounts with addresses they do not own and use the API immediately, which enables impersonation, spam and abuse of trial or invite flows.',
            remediation: 'Withhold sessions (or restrict them to a verification-only scope) until the address is confirmed through a link or code sent to it.',
            evidence: [evidence(created, 'Synthetic signup.'), evidence(used, 'The new token used on a read-only endpoint.')],
          });
        } else if (used && is2xx(used) && !verified) {
          report({
            key: `identity|no-verification-step|${where}`,
            title: 'Signup issues a session immediately; no email verification step is visible',
            severity: 'medium',
            confidence: 'low',
            endpoint: where,
            description: 'Signup returned a working token and no verification state. The API may verify email out of band, so this needs human review.',
            impact: 'If addresses are never verified, accounts can be created for addresses the signer does not own.',
            remediation: 'Confirm that addresses are verified before sensitive actions, and expose the verification state in the API.',
            evidence: [evidence(created), evidence(used)],
          });
        }
      }

      // The same address in a different case or plus-form must not create a second account.
      if (emailField) {
        const dupEmail = String(body[emailField]).replace(/^[^@]+/, (l) => l.toUpperCase());
        const dup = await send({ ...body, [emailField]: dupEmail }, 'duplicate email in a different case');
        if (!dup.skipped && is2xx(dup)) {
          report({
            key: `identity|duplicate-email|${where}`,
            title: 'Email addresses are not normalized: a case variant creates a second account',
            severity: 'medium',
            endpoint: where,
            param: emailField,
            description: `A second signup with "${dupEmail}" (same address, different case) succeeded alongside "${body[emailField]}".`,
            impact: 'Duplicate identities allow account confusion, bypass of one-account-per-person rules and takeover tricks around password reset.',
            remediation: 'Normalize email (lowercase the domain and, as your policy allows, the local part) before storing, and enforce uniqueness on the normalized value.',
            evidence: [evidence(dup, 'Synthetic addresses only.')],
          });
        }
      }

      // Weak passwords.
      if (passwordField) {
        const weak = await send(cloneBody(ep, syn, { [passwordField]: syn.weakPassword }), 'weak password');
        if (!weak.skipped && is2xx(weak)) {
          report({
            key: `identity|weak-password|${where}`,
            title: 'A trivially weak password is accepted',
            severity: 'medium',
            endpoint: where,
            param: passwordField,
            description: `"${syn.weakPassword}" was accepted as a password and returned HTTP ${weak.status}.`,
            impact: 'Accounts can be guessed or brute-forced, especially without rate limiting.',
            remediation: 'Enforce a minimum length (12+ recommended) and check against a list of breached or common passwords on the server.',
            evidence: [evidence(weak)],
          });
        }
      }
    }

    // Account enumeration through different login responses.
    for (const ep of logins) {
      const known = accounts.map((a) => a.resourceIds?.email).find(Boolean);
      const emailField = Object.keys(ep.bodyExample || {}).find(isEmailField) || 'email';
      const passwordField = Object.keys(ep.bodyExample || {}).find(isPasswordField) || 'password';
      const where = label(ep);
      if (!known) { log(`${where}: enumeration check needs a test account with email=<address> among its resources; skipped.`); continue; }
      const req = buildRequest(ep, valuesFor(ep, null));
      const unknown = syn.email('nobody');
      const wrong = syn.password();
      const send = (email, purpose) => client.sendSynthetic(ep, { ...req, body: { [emailField]: email, [passwordField]: wrong }, purpose });
      const a = await send(known, 'login with a wrong password, known test account');
      if (a.skipped) continue;
      const b = await send(unknown, 'login with a wrong password, unknown address');
      if (b.skipped) continue;
      const same = a.status === b.status && similarity(stripEmails(a.body, known, unknown), stripEmails(b.body, known, unknown)) >= 0.9;
      if (!same) {
        report({
          key: `identity|enumeration|${where}`,
          title: 'Login responses reveal whether an account exists',
          severity: 'medium',
          confidence: 'medium',
          endpoint: where,
          description: `A wrong password for a known test account returned HTTP ${a.status}; the same for an unknown address returned HTTP ${b.status}${a.status === b.status ? ' with a different body' : ''}.`,
          impact: 'Attackers can build lists of valid accounts and target them with password guessing and phishing.',
          remediation: 'Return the same status, body and timing for unknown accounts and wrong passwords ("invalid email or password").',
          evidence: [evidence(a, 'Known test account, wrong password.'), evidence(b, 'Unknown synthetic address, wrong password.')],
        });
      }
    }
  },
};
