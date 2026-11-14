# Decisions

Only decisions stated in the code or docs. Format: decision, reason, source.

- **No runtime dependencies, no build step for the app.** Keeps the install and audit surface small. Source: `package.json`, `README.md` (Quick start).
- **Strict CSP (`default-src 'self'`), self-hosted fonts.** No third-party assets at runtime. Source: `PRODUCT.md`, `README.md` (Layout).
- **Single-process JSON file store.** Known limit; a database is an architecture decision. Source: `PRODUCT.md`, `CLAUDE.md`.
- **No public sign-up; admins issue accounts, access lasts 30 days or until restart.** Invite-only for the hosted demo. Source: `SECURITY.md`, `README.md`.
- **Passwords hashed with scrypt; sessions stored as SHA-256 hashes; test credentials AES-256-GCM encrypted.** Source: `SECURITY.md`.
- **CSRF: `X-BreakAPI: 1` header plus same-origin check; `SameSite=Strict` cookies.** A cross-site simple request cannot send the header. Source: `SECURITY.md`.
- **Exact-host scope, no wildcards, redirects never followed.** Requests must not leave the authorized hosts. Source: `SECURITY.md`, `README.md`.
- **DELETE is never sent; writes need the authorization's write switch and a per-endpoint opt-in, with synthetic data.** Source: `SECURITY.md`, `CLAUDE.md`.
- **Hard server-side ceilings on budget, rate and duration.** They hold even if stored controls are edited. Source: `SECURITY.md`, `README.md`.
- **Hosted mode refuses localhost and private targets by default.** Source: `.env.example`.
- **Lab playground uses a separate simulation backend (`breakAPI-sim`), reached by URL or embedded.** Source: `.env.example`, `README.md`, `SECURITY.md`.
- **Sim control key only over https; client does not follow redirects.** A redirect cannot carry the key elsewhere. Source: `SECURITY.md`.
- **Lab bounded by a daily run cap (`BREAKAPI_LAB_DAILY_RUNS`).** Source: `.env.example`, `SECURITY.md`.
- **Frontend on Netlify, backend on Replit; Netlify-only build script.** Free-plan demo hosting. Source: `netlify.toml`, `docs/DEPLOY-NETLIFY.md`.
- **Tests use the Node built-in runner with an explicit glob.** Node 24 compatibility. Source: `package.json`, commit `650bd04`.
