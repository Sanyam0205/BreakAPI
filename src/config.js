import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const bool = (v, fallback) => (v === undefined || v === '' ? fallback : /^(1|true|yes|on)$/i.test(String(v)));
const int = (v, fallback) => (Number.isFinite(Number(v)) && v !== '' && v !== undefined ? Math.round(Number(v)) : fallback);

/**
 * Reads configuration from the environment. Production defaults are the safe ones:
 * local and private-network targets are refused, signup is closed, and the server
 * refuses to start without the settings a public deployment needs.
 */
export function loadConfig(env = process.env, overrides = {}) {
  const production = (env.BREAKAPI_ENV || env.NODE_ENV) === 'production';
  const c = {
    env: production ? 'production' : 'development',
    production,
    port: int(env.PORT, 7300),
    host: env.HOST || (production ? '0.0.0.0' : '127.0.0.1'),
    dataDir: env.BREAKAPI_DATA || join(ROOT, 'data'),
    publicUrl: (env.BREAKAPI_PUBLIC_URL || '').replace(/\/$/, ''),
    secretKey: env.BREAKAPI_SECRET_KEY || '',
    trustProxy: bool(env.BREAKAPI_TRUST_PROXY, false),
    // Targets on this machine or its private network. Fine on a laptop, an SSRF risk on a shared server.
    allowLocalTargets: bool(env.BREAKAPI_ALLOW_LOCAL_TARGETS, !production),
    allowPrivateTargets: bool(env.BREAKAPI_ALLOW_PRIVATE_TARGETS, !production),
    signup: ['open', 'closed'].includes(env.BREAKAPI_SIGNUP) ? env.BREAKAPI_SIGNUP : 'closed',
    sessionHours: int(env.BREAKAPI_SESSION_HOURS, 12),
    maxConcurrentScans: int(env.BREAKAPI_MAX_CONCURRENT_SCANS, 4),
    mail: {
      mode: env.SMTP_HOST ? 'smtp' : 'outbox',
      from: env.BREAKAPI_MAIL_FROM || 'breakAPI <no-reply@breakapi.invalid>',
      host: env.SMTP_HOST || '',
      port: int(env.SMTP_PORT, 465),
      secure: bool(env.SMTP_SECURE, int(env.SMTP_PORT, 465) === 465),
      startTls: bool(env.SMTP_STARTTLS, int(env.SMTP_PORT, 465) === 587),
      user: env.SMTP_USER || '',
      pass: env.SMTP_PASS || '',
    },
    ...overrides,
  };
  if (overrides.mail) c.mail = { ...c.mail, ...overrides.mail };
  return c;
}

/** Problems that must stop a production server from starting. */
export function configProblems(c) {
  if (!c.production) return [];
  const problems = [];
  if (!/^https:\/\//.test(c.publicUrl)) problems.push('BREAKAPI_PUBLIC_URL must be the https:// address users reach the app on.');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(c.secretKey)) problems.push('BREAKAPI_SECRET_KEY must be a base64-encoded 32-byte key (generate one with: openssl rand -base64 32).');
  if (c.mail.mode !== 'smtp') problems.push('SMTP_HOST (and SMTP_USER / SMTP_PASS) must be set so verification and reset emails can be delivered.');
  return problems;
}

/** Non-secret view of the configuration for the admin page and startup log. */
export function publicConfig(c) {
  return {
    env: c.env,
    publicUrl: c.publicUrl || null,
    signup: c.signup,
    allowLocalTargets: c.allowLocalTargets,
    allowPrivateTargets: c.allowPrivateTargets,
    trustProxy: c.trustProxy,
    sessionHours: c.sessionHours,
    maxConcurrentScans: c.maxConcurrentScans,
    mail: c.mail.mode === 'smtp' ? `smtp://${c.mail.host}:${c.mail.port}` : 'outbox (written to the data directory, not delivered)',
    secretKey: c.secretKey ? 'from environment' : 'generated file in the data directory',
  };
}

let current = loadConfig({}, {});
export const getConfig = () => current;
export const setConfig = (c) => { current = c; };
