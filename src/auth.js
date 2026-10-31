import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';

const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const COMMON = new Set(['password', 'password1', 'password123', '123456789012', 'qwertyuiop', 'letmeinplease', 'iloveyou1234', 'administrator', 'changemeplease', 'welcome12345', 'breakapibreakapi', 'correcthorsebatterystaple']);

export const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const normalizeEmail = (e) => String(e || '').trim().toLowerCase();
export const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && !/@.*@/.test(e) && e.length <= 254;

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = String(stored || '').split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64');
  const got = scryptSync(String(password), Buffer.from(salt, 'base64'), expected.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return got.length === expected.length && timingSafeEqual(got, expected);
}

// A fixed hash so unknown accounts take as long as wrong passwords (no timing oracle).
const DUMMY = hashPassword(randomToken());
export const burnTime = (password) => verifyPassword(password, DUMMY);

/** Returns a problem string, or null when the password is acceptable. */
export function passwordProblem(password, email = '') {
  const p = String(password || '');
  if (p.length < 12) return 'Use at least 12 characters.';
  if (p.length > 200) return 'Use at most 200 characters.';
  if (COMMON.has(p.toLowerCase())) return 'That password is too common.';
  if (email && p.toLowerCase().includes(normalizeEmail(email).split('@')[0]) && normalizeEmail(email).split('@')[0].length >= 4) return 'Don’t include your email name in the password.';
  if (/^(.)\1+$/.test(p)) return 'That password is too simple.';
  return null;
}

/** Fixed-window counters for login, signup and reset throttling. */
export class RateLimiter {
  constructor() {
    this.windows = new Map();
    this.timer = setInterval(() => {
      const now = Date.now();
      for (const [k, w] of this.windows) if (w.resetAt <= now) this.windows.delete(k);
    }, 60_000);
    this.timer.unref();
  }

  /** Counts a hit; returns { ok, retryAfter } where retryAfter is seconds. */
  hit(key, limit, windowMs) {
    const now = Date.now();
    let w = this.windows.get(key);
    if (!w || w.resetAt <= now) {
      w = { count: 0, resetAt: now + windowMs };
      this.windows.set(key, w);
    }
    w.count++;
    return { ok: w.count <= limit, retryAfter: Math.ceil((w.resetAt - now) / 1000) };
  }

  reset(key) {
    this.windows.delete(key);
  }

  stop() {
    clearInterval(this.timer);
  }
}

export function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    emailVerified: !!u.emailVerifiedAt,
    disabled: !!u.disabledAt,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt || null,
    invited: !u.passwordHash,
  };
}
