import { createHash } from 'node:crypto';

// Plain-language DRAFT. Keep all wording here so counsel can replace it in one place.
// Changing any clause changes the version hash, so existing authorizations must be re-recorded.
export const UNDERTAKING_VERSION = '2026-10-draft-1';

export const LEGAL_NOTICE = 'This undertaking is a plain-language draft, not legal advice. Have a qualified lawyer review it, and your authority to test these systems, before you rely on it.';

export const UNDERTAKING_CLAUSES = [
  'I own the systems listed in scope, or I hold written permission from their owner to test them.',
  'I am responsible for how breakAPI is used under this authorization, including any effect on availability, data, costs or third parties.',
  'The scope lists only systems I am authorized to test. It includes no third-party service, shared platform or public target that I do not control.',
  'I will use only dedicated test accounts and synthetic data, never real customer accounts or personal data.',
  'The people who operate and monitor these systems know a test is planned, and I have checked any rules my hosting or cloud provider sets for security testing.',
  'I understand that breakAPI cannot confirm that I own or may test these systems, and that accepting this undertaking does not give me legal permission or remove legal risk.',
];

export const AUTH_LIMITATIONS = [
  'A verification challenge shows that someone could publish a token at a location on the target at one moment. It does not prove legal ownership or authority to test.',
  'A DNS record proves control of a domain name, not of a particular service, port or the data behind it. Shared hosting, CDNs, wildcard DNS and subdomain takeover can all defeat a challenge.',
  'The accepted undertaking is a self-declaration. It does not establish that you are authorized and does not remove legal risk.',
  'Identity checks are limited to email: the test runner must have a verified account email, and an authorizer other than the test runner must confirm from a link sent to their address. That shows someone controls the inbox, not that they hold authority over the systems.',
  'Hosting and cloud providers, contracts, data-protection rules and computer-misuse laws can impose requirements that breakAPI does not check.',
  'breakAPI cannot tell whether data in a target is real. Use dedicated test accounts and synthetic data only.',
  'Scope, rate limits and stop conditions are enforced by breakAPI’s own client. They do not control what the target or anything between you and it does with the requests.',
  'Get legal advice before testing anything beyond your own local or development systems.',
];

export function hashUndertaking() {
  return createHash('sha256').update([UNDERTAKING_VERSION, ...UNDERTAKING_CLAUSES].join('\n')).digest('hex');
}

const norm = (s) => String(s ?? '').trim().replace(/\s+/g, ' ').toLowerCase();

/** The typed name must repeat the authorizer's name: a deliberate act, not a pre-ticked box. */
export function typedNameMatches(typedName, authorizerName) {
  return !!norm(typedName) && norm(typedName) === norm(authorizerName);
}
