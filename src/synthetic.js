import { randomBytes } from 'node:crypto';

// Synthetic data only. Emails use the reserved .invalid TLD (RFC 2606), so they can never be delivered.
export function createSynthetic(scanId) {
  const marker = `breakapi-${String(scanId).replace(/^scan_/, '').slice(0, 8)}`;
  let n = 0;
  const unique = () => `${marker}-${++n}-${randomBytes(2).toString('hex')}`;
  return {
    marker,
    name: () => unique(),
    email: (tag = '') => `${unique()}${tag ? `+${tag}` : ''}@example.invalid`,
    password: () => `Bp!${randomBytes(6).toString('hex')}`,
    weakPassword: '123456',
    malformedEmails: ['not-an-email', 'user@@example.invalid', 'a@b'],
  };
}

export const isEmailField = (name) => /e-?mail/i.test(name);
export const isNumericField = (name) => /(quantity|qty|count|amount|price|total|discount|age|balance|limit|points)/i.test(name);
export const isPrivilegeField = (name) => /^(role|roles|is_?admin|admin|verified|email_?verified|is_?staff|permissions|scope|balance|credits)$/i.test(name);
export const isPasswordField = (name) => /pass(word)?$/i.test(name);

// A stricter check than most servers need; used only to decide whether a *response* contains a bad address.
export const looksLikeEmail = (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) && !v.includes('..') && !/@.*@/.test(v);
