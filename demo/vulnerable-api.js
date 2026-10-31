// A deliberately vulnerable API for trying breakAPI locally, and the target of the built-in demo lab,
// which binds it to loopback only. NEVER expose it to a network.
// Every weakness is marked VULNERABLE.
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const SECRET = 'secret'; // VULNERABLE: guessable signing key

export const stats = { requests: 0, deletes: 0, writes: 0, signups: 0, orders: 0, logins: 0 };

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

export function sign(payload) {
  const h = b64({ alg: 'HS256', typ: 'JWT' });
  const p = b64(payload);
  return `${h}.${p}.${createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url')}`;
}

function verify(token, fixed) {
  try {
    const [h, p, s] = token.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url'));
    const payload = JSON.parse(Buffer.from(p, 'base64url'));
    if (header.alg === 'none') return fixed ? null : payload; // VULNERABLE: unsigned tokens accepted
    if (createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url') !== s) return null;
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export function demoTokens() {
  const iat = Math.floor(Date.now() / 1000);
  return {
    alice: sign({ sub: 1, role: 'user', iat, exp: iat + 86400 }),
    bob: sign({ sub: 2, role: 'user', iat, exp: iat + 86400 }),
    root: sign({ sub: 3, role: 'admin', iat, exp: iat + 86400 }),
  };
}

/**
 * Options (also read from env by the CLI below):
 *   fixed        DEMO_FIXED=1        patch IDOR, missing auth, admin check, alg=none and CORS (for retest demos)
 *   rateLimit    DEMO_RATE_LIMIT=N   answer 429 after N requests per second per client
 *   verifyToken  DEMO_VERIFY_TOKEN   serve it at /.well-known/breakapi-verification.txt (a string, or a function returning one)
 */
export function createDemoServer({ fixed = false, rateLimit = 0, verifyToken = '' } = {}) {
  // Each server has its own data, so one run's signups and orders never show up in another.
  const users = {
    1: { id: 1, name: 'Alice', email: 'alice@demo.test', role: 'user' },
    2: { id: 2, name: 'Bob', email: 'bob@demo.test', role: 'user' },
    3: { id: 3, name: 'Root', email: 'root@demo.test', role: 'admin' },
  };
  const orders = { 1: [{ id: 101, item: 'Keyboard' }], 2: [{ id: 201, item: 'Monitor' }] };
  const orderPrice = 49.9; // the server-side price of the demo item
  let nextUserId = 100;
  let nextOrderId = 5000;
  const recentOrders = new Map();
  const invoices = { 1: { id: 1, owner: 1, total: 120.5 }, 2: { id: 2, owner: 2, total: 89 } };
  const hits = new Map();
  // What this target actually received, counted on its side rather than the scanner's.
  const seen = { requests: 0, writes: 0, deletes: 0 };
  const server = http.createServer((req, res) => {
    stats.requests++;
    seen.requests++;
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) seen.writes++;
    if (req.method === 'DELETE') seen.deletes++;
    const url = new URL(req.url, 'http://demo');
    const headers = { 'x-powered-by': 'DemoServer/1.0', 'content-type': 'application/json' }; // VULNERABLE: tech disclosure
    if (req.headers.origin && (!fixed || req.headers.origin === 'https://app.demo.test')) {
      headers['access-control-allow-origin'] = req.headers.origin; // VULNERABLE: reflects any origin…
      headers['access-control-allow-credentials'] = 'true'; // …with credentials
    }
    const send = (status, body, extra = {}) => {
      res.writeHead(status, { ...headers, ...extra });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    const route = (method, re) => req.method === method && url.pathname.match(re);
    const auth = verify((req.headers.authorization || '').replace(/^Bearer /, ''), fixed);
    let m;

    if (rateLimit) {
      const key = req.headers.authorization || req.socket.remoteAddress;
      const second = Math.floor(Date.now() / 1000);
      const h = hits.get(key);
      const count = h && h.second === second ? h.count + 1 : 1;
      hits.set(key, { second, count });
      if (count > rateLimit) return send(429, { error: 'rate limited' }, { 'retry-after': '1' });
    }
    const verifyValue = typeof verifyToken === 'function' ? verifyToken() : verifyToken;
    if (verifyValue && route('GET', /^\/\.well-known\/breakapi-verification\.txt$/)) return send(200, verifyValue, { 'content-type': 'text/plain' });

    if (req.method === 'OPTIONS') return send(204, '');
    if (route('GET', /^\/openapi\.json$/)) return send(200, readFileSync(new URL('./openapi.json', import.meta.url), 'utf8'));
    if (route('GET', /^\/\.env$/)) return send(200, 'DATABASE_URL=postgres://app:hunter2@db/app\nJWT_SECRET=secret\n', { 'content-type': 'text/plain' }); // VULNERABLE
    if (route('GET', /^\/api\/health$/)) return send(200, { ok: true });
    if ((m = route('GET', /^\/api\/invoices\/(\d+)$/))) { // VULNERABLE: no authentication at all
      if (fixed && (!auth || invoices[m[1]]?.owner !== auth.sub)) return send(auth ? 404 : 401, { error: auth ? 'not found' : 'unauthorized' });
      return invoices[m[1]] ? send(200, invoices[m[1]]) : send(404, { error: 'not found' });
    }

    // Parses a small JSON request body, then runs the handler.
    const withBody = (handler) => {
      let raw = '';
      req.on('data', (c) => { if (raw.length < 16_384) raw += c; });
      req.on('end', () => {
        let body = {};
        try { body = raw ? JSON.parse(raw) : {}; } catch { return send(400, { error: 'invalid JSON' }); }
        handler(body);
      });
    };
    const emailOk = (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) && !/@.*@/.test(v);

    if (route('POST', /^\/api\/login$/)) {
      return withBody((body) => {
        stats.logins++;
        const known = Object.values(users).some((u) => u.email === body.email);
        const cookie = fixed ? 'sid=demo-session; Path=/; HttpOnly; SameSite=Lax' : 'sid=demo-session; Path=/'; // VULNERABLE: no HttpOnly / SameSite
        // VULNERABLE: different answers for unknown accounts and wrong passwords (account enumeration)
        if (fixed || known) return send(401, { error: fixed ? 'invalid email or password' : 'wrong password' }, { 'set-cookie': cookie });
        return send(404, { error: 'no such user' }, { 'set-cookie': cookie });
      });
    }
    if (route('POST', /^\/api\/users$/)) {
      return withBody((body) => {
        stats.signups++;
        stats.writes++;
        if (fixed) {
          if (!emailOk(body.email)) return send(400, { error: 'invalid email' });
          if (typeof body.password !== 'string' || body.password.length < 8) return send(400, { error: 'password too short' });
          if (body.age !== undefined && !(Number.isInteger(body.age) && body.age >= 0 && body.age <= 130)) return send(400, { error: 'invalid age' });
          if (Object.values(users).some((u) => String(u.email).toLowerCase() === body.email.toLowerCase())) return send(409, { error: 'email already registered' });
        }
        const id = nextUserId++;
        const now = new Date().toISOString();
        // VULNERABLE: no server-side validation, role and verification state come from the client, duplicates allowed
        users[id] = { id, name: body.name, email: body.email, age: body.age, role: fixed ? 'user' : (body.role || 'user'), email_verified: fixed ? false : (body.email_verified ?? false), createdAt: now, updatedAt: now };
        const record = { id, email: body.email, role: users[id].role, email_verified: users[id].email_verified, age: body.age, createdAt: now, updatedAt: now };
        // VULNERABLE: a working session before the email is verified
        return send(201, fixed ? { ...record, message: 'check your email to continue' } : { ...record, token: sign({ sub: id, role: users[id].role, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 }) });
      });
    }

    if (!auth) return send(url.pathname.startsWith('/api/') ? 401 : 404, { error: url.pathname.startsWith('/api/') ? 'unauthorized' : 'not found' });

    if (route('GET', /^\/api\/me$/)) return send(200, users[auth.sub]);
    if (route('GET', /^\/api\/profile-data$/)) { // VULNERABLE: stored data is internally inconsistent
      return send(200, fixed
        ? { email: 'dana@demo.test', age: 34, quantity: 3, createdAt: '2026-09-01T00:00:00Z', updatedAt: '2026-10-01T00:00:00Z', birthDate: '1992-04-02' }
        : { email: 'dana@@demo', age: 212, quantity: -3, createdAt: '2026-10-01T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z', birthDate: '1850-01-01', email_verified: false, role: 'admin' });
    }
    if (route('POST', /^\/api\/orders$/)) {
      return withBody((body) => {
        stats.orders++;
        stats.writes++;
        if (fixed) {
          if (!Number.isInteger(body.quantity) || body.quantity < 1 || body.quantity > 100) return send(400, { error: 'invalid quantity' });
          const key = `${auth.sub}:${JSON.stringify(body)}`;
          const dup = recentOrders.get(key);
          if (dup) return send(200, dup); // idempotent replay
          const order = { id: nextOrderId++, item: body.item, quantity: body.quantity, price: orderPrice, total: body.quantity * orderPrice };
          recentOrders.set(key, order);
          return send(201, order);
        }
        // VULNERABLE: quantity and price come from the client without checks; each replay is a new order
        return send(201, { id: nextOrderId++, item: body.item, quantity: body.quantity, price: body.price, total: body.quantity * body.price });
      });
    }
    if ((m = route('GET', /^\/api\/users\/(\d+)$/))) { // VULNERABLE: IDOR — no ownership check
      if (fixed && Number(m[1]) !== auth.sub && auth.role !== 'admin') return send(404, { error: 'not found' });
      return users[m[1]] ? send(200, users[m[1]]) : send(404, { error: 'not found' });
    }
    if ((m = route('GET', /^\/api\/users\/(\d+)\/orders$/))) { // secure: ownership enforced
      if (Number(m[1]) !== auth.sub) return send(403, { error: 'forbidden' });
      return send(200, orders[m[1]] || []);
    }
    if (route('GET', /^\/api\/admin\/users$/)) { // VULNERABLE: no role check
      if (fixed && auth.role !== 'admin') return send(403, { error: 'forbidden' });
      return send(200, Object.values(users));
    }
    if (route('GET', /^\/api\/search$/)) {
      const q = url.searchParams.get('q') || '';
      if (/['"]/.test(q)) { // VULNERABLE: simulated SQL concatenation + stack trace leak
        const err = new Error(`SQLITE_ERROR: unrecognized token: "'${q}"`);
        return send(500, err.stack, { 'content-type': 'text/plain' });
      }
      return send(200, Object.values(users).filter((u) => u.name.toLowerCase().includes(q.toLowerCase())).map(({ id, name }) => ({ id, name })));
    }
    if (route('GET', /^\/api\/greet$/)) { // VULNERABLE: reflected XSS
      return send(200, `<!doctype html><p>Hello, ${url.searchParams.get('name') || 'friend'}!</p>`, { 'content-type': 'text/html' });
    }
    if ((m = route('PATCH', /^\/api\/users\/(\d+)$/))) {
      stats.writes++;
      return send(Number(m[1]) === auth.sub ? 200 : 403, Number(m[1]) === auth.sub ? users[m[1]] : { error: 'forbidden' });
    }
    if ((m = route('DELETE', /^\/api\/users\/(\d+)$/))) {
      stats.deletes++;
      delete users[m[1]];
      return send(204, '');
    }
    return send(404, { error: 'not found' });
  });
  server.seen = seen;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 4010);
  const host = process.env.DEMO_HOST || '127.0.0.1';
  const options = {
    fixed: process.env.DEMO_FIXED === '1',
    rateLimit: Number(process.env.DEMO_RATE_LIMIT || 0),
    verifyToken: process.env.DEMO_VERIFY_TOKEN || '',
  };
  createDemoServer(options).listen(port, host, () => {
    const t = demoTokens();
    console.log(`Vulnerable demo API on http://${host === '0.0.0.0' ? 'localhost' : host}:${port}  (spec: /openapi.json)`);
    console.log(`Mode: ${options.fixed ? 'FIXED (some weaknesses patched)' : 'vulnerable'}${options.rateLimit ? ` · rate limit ${options.rateLimit}/s` : ''}${options.verifyToken ? ' · serving verification token' : ''}`);
    console.log('Test accounts (valid 24h):');
    console.log(`  alice  user   id=1  ${t.alice}`);
    console.log(`  bob    user   id=2  ${t.bob}`);
    console.log(`  root   admin  id=3  ${t.root}`);
  });
}
