// Creates a fully configured demo project through breakAPI's own API (the same calls the UI makes).
// Usage: node testdata/seed.mjs [--app http://127.0.0.1:7300] [--demo localhost:4010] [--name "Demo API"] [--email a@b.co --password …] [--writes] [--scan]
//   On a fresh server it creates the first admin (default dana@example.com / demo-passphrase-change-me); otherwise it signs in.
//   --writes  also authorize write requests and opt the demo's signup, login and order endpoints in to synthetic
//             writes. Both are human decisions in the real app; the script makes them for the local demo only.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { demoTokens } from '../demo/vulnerable-api.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const appUrl = arg('app', 'http://127.0.0.1:7300');
const demoHost = arg('demo', 'localhost:4010');
const name = arg('name', 'Demo API — local');
const dataDir = process.env.BREAKAPI_DATA || join(root, 'data');
const email = arg('email', process.env.BREAKAPI_EMAIL || 'dana@example.com');
const password = arg('password', process.env.BREAKAPI_PASSWORD || 'demo-passphrase-change-me');
let sid = '';

async function api(method, path, body) {
  const r = await fetch(appUrl + path, {
    method,
    headers: { 'content-type': 'application/json', 'x-breakapi': '1', ...(sid ? { cookie: `bp_sid=${sid}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const set = r.headers.get('set-cookie');
  if (set && /bp_sid=([^;]+)/.test(set)) sid = set.match(/bp_sid=([^;]+)/)[1];
  const data = await r.json();
  if (!r.ok) throw new Error(`${method} ${path}: ${data.error}`);
  return data;
}

// On a fresh server, create the first admin with the setup token; otherwise sign in.
let setupToken = '';
try { setupToken = readFileSync(join(dataDir, 'setup-token'), 'utf8').trim(); } catch { /* already set up */ }
if (setupToken) {
  await api('POST', '/api/auth/setup', { setupToken, name: 'Dana Ruiz', email, password });
  console.log(`Created the first administrator: ${email} / ${password}  (change this password)`);
} else {
  await api('POST', '/api/auth/login', { email, password });
}
const me = (await api('GET', '/api/auth/me')).user;

const p = await api('POST', '/api/projects', { name });
await api('PUT', `/api/projects/${p.id}/authorization`, {
  authorizerName: me.name,
  authorizerEmail: me.email, // self-authorized: the signed-in, verified user
  authorizerRole: 'API owner',
  relationship: 'owner',
  allowedHosts: [demoHost],
  allowedTests: ['config', 'exposure', 'authn', 'authz', 'input', 'validation', 'identity', 'logic', 'ratelimit'],
  allowWriteMethods: process.argv.includes('--writes'),
  expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString(),
  attestations: { ownsOrAuthorized: true, scopeAccurate: true, acceptsImpact: true },
  undertaking: { accepted: true, typedName: me.name },
});
await api('POST', `/api/projects/${p.id}/import`, { format: 'openapi', content: readFileSync(join(root, 'demo/openapi.json'), 'utf8') });
await api('PUT', `/api/projects/${p.id}/target`, { baseUrl: `http://${demoHost}` });
const t = demoTokens();
for (const [label, role, secret, id] of [['alice', 'user', t.alice, '1'], ['bob', 'user', t.bob, '2']]) {
  await api('POST', `/api/projects/${p.id}/accounts`, { label, role, authType: 'bearer', secret, resourceIds: { id, email: `${label}@demo.test` } });
}
await api('PUT', `/api/projects/${p.id}/controls`, { maxRequests: 500, rps: 20, burstRps: 50, rateLimitBurst: 30, timeoutMs: 8000, stopOnErrorStreak: 10, monitoringContact: 'dana@example.com' });
if (process.argv.includes('--writes')) {
  const current = await api('GET', `/api/projects/${p.id}`);
  for (const e of current.target.endpoints.filter((x) => ['signup', 'login', 'order'].includes(x.kind))) {
    await api('PATCH', `/api/projects/${p.id}/endpoints/${e.id}`, { syntheticWrites: true });
  }
}
console.log(`Project ready: ${appUrl}/#/p/${p.id}/scans`);
if (process.argv.includes('--scan')) {
  const s = await api('POST', `/api/projects/${p.id}/scans`, {});
  console.log(`Scan started:  ${appUrl}/#/s/${s.id}`);
}
