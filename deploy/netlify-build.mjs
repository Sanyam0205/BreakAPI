// Builds the Netlify site: the static frontend plus a proxy to the breakAPI backend.
//
//   BACKEND_URL=https://your-backend.example node deploy/netlify-build.mjs
//
// The browser only ever talks to the Netlify domain. Netlify forwards /api/*, /reports/* and /healthz to the
// backend ("rewrites" with status 200), so cookies stay first-party and no CORS is needed.
import { cpSync, rmSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist');

const raw = (process.env.BACKEND_URL || '').trim().replace(/\/+$/, '');
let backend;
try {
  backend = new URL(raw);
} catch {
  console.error('BACKEND_URL is not set (or not a URL). In Netlify: Site configuration → Environment variables → BACKEND_URL = https://<your backend>.');
  process.exit(1);
}
if (backend.protocol !== 'https:') {
  console.error(`BACKEND_URL must be https:// (got ${backend.protocol}//). Cookies and emailed links need HTTPS end to end.`);
  process.exit(1);
}
if (backend.pathname !== '/' || backend.search || backend.hash) {
  console.error('BACKEND_URL must be just the origin, for example https://myapp.example.com (no path).');
  process.exit(1);
}
const target = backend.origin;

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
if (!existsSync(join(root, 'public', 'index.html'))) {
  console.error('public/index.html not found; run this from the repository root.');
  process.exit(1);
}
cpSync(join(root, 'public'), out, { recursive: true });
// Documentation inside public/fonts is not part of the site.
rmSync(join(out, 'fonts', 'README.md'), { force: true });

// "200!" = rewrite (the address bar keeps the Netlify URL) and always win over a file of the same name.
writeFileSync(join(out, '_redirects'), [
  `/api/*      ${target}/api/:splat      200!`,
  `/reports/*  ${target}/reports/:splat  200!`,
  `/healthz    ${target}/healthz         200!`,
  '',
].join('\n'));

// Same policy the backend sends itself. (Netlify applies these to the static files it serves; proxied
// responses carry the backend's own headers.)
writeFileSync(join(out, '_headers'), `/*
  Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  X-Frame-Options: DENY
  Cross-Origin-Opener-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains

/fonts/*
  Cache-Control: public, max-age=31536000, immutable
`);

console.log(`Built ${out}`);
console.log(`Proxying /api/*, /reports/*, /healthz → ${target}`);
