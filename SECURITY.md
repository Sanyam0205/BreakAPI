# breakAPI security model

breakAPI is itself a tool that sends traffic to other people's systems, so it is designed around two questions: *who is allowed to use it*, and *what may it be pointed at*. This document records the controls, the review that produced them, and what remains open.

## Who can use it

| Control | Implementation |
| --- | --- |
| Accounts | Email + password. Passwords are hashed with scrypt (N=16384, r=8, p=1, per-user salt). Minimum 12 characters; common and trivially repetitive passwords and passwords containing the email name are refused. |
| Roles | `admin` (manage users, server settings, system audit) and `user`. The last active admin cannot be demoted, disabled or deleted. |
| First admin | Created once with a random setup token printed at startup and stored owner-readable in the data directory; deleted after use. |
| Issued accounts | No public sign-up. An admin creates each user account and passes on a password and a random 144-bit setup token, shown once and stored only as hashes. Both are required at every sign-in, and failures look the same whichever part was wrong. Access ends after 30 days or when the app restarts, whichever is first. Each account has one session at a time, with no idle timeout. An ended account's running scans are stopped. |
| Sessions | 256-bit random id in an `HttpOnly; SameSite=Strict; Path=/` cookie, `Secure` behind HTTPS. Only a SHA-256 hash is stored. Rotated on every sign-in. For admins: idle timeout (default 12 h) and absolute 7 days. For issued accounts: until their access ends. All are ended on sign-out, "sign out everywhere", password change (other devices) and reset (all devices), and admin disable. |
| Brute force | Sign-in limited per IP (30 / 15 min) and per account (8 / 15 min) with `Retry-After`; sign-up, reset, resend and confirmation endpoints are also limited. Failed sign-ins are audited. |
| Enumeration | Sign-in, sign-up and password reset give the same answer whether or not an account exists; unknown accounts burn the same scrypt time. |
| Email links | Verification (48 h), reset (1 h) and authorizer confirmation (72 h) links are single-use random tokens stored hashed, invalidated when re-issued, and built from `BREAKAPI_PUBLIC_URL` (never the request Host header). |
| Test runner verification | Creating projects, recording authorizations, changing targets and starting scans require a **verified email**. Issued accounts count as verified because an admin vouches for them; the inbox itself is not checked. Every authorization records who recorded it and every scan records who started it, with their verification time; both appear in reports. |
| Authorizer confirmation | If the authorizer named on an authorization is not the signed-in user, they get an email link showing the exact scope, the limitations and the undertaking. Nothing can be tested until they accept it by typing their name; they can also decline. Recording a newer authorization or resending invalidates older links. |
| Project isolation | Projects, findings, reports, scans and audit logs are visible only to project members. Non-members get 404 (not 403) so ids can't be probed. Only owners delete projects or manage members. Admins have no implicit access to project data. |
| CSRF | Every state-changing request needs an `X-BreakAPI: 1` header (which a cross-site form or simple request cannot send) **and** a same-origin `Origin` when one is present. Cookies are `SameSite=Strict`. |
| Browser hardening | Strict CSP (`default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`), no inline script or style, `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, COOP, a restrictive Permissions-Policy, HSTS over HTTPS, `no-store` on API responses. All dynamic content is HTML-escaped (target responses shown as evidence are attacker-controlled by definition). |
| Input handling | JSON bodies are size-limited (16 KB on auth routes, 5 MB elsewhere) and parsed with `__proto__`/`constructor`/`prototype` keys dropped (no prototype pollution). Fields have length and count caps. |
| Secrets at rest | Test credentials are AES-256-GCM encrypted with `BREAKAPI_SECRET_KEY` (or a generated key file in development), masked in logs and evidence, never returned by the API, and deleted when the authorization expires or is revoked. |

## What it can be pointed at

| Control | Implementation |
| --- | --- |
| Consent | A recorded authorization (who, basis, scope, tests, expiry ≤ 90 days, three attestations) plus an accepted, versioned, hashed undertaking — by the authorizer themselves. |
| Scope | Requests go only to hosts listed exactly in the authorization; no wildcards; redirects are never followed. |
| Proof of control | Every non-local host in scope must pass a DNS-TXT or well-known-file challenge bound to the current authorization, valid 24 h, re-run before every scan (fail closed). |
| SSRF | All outbound requests (scans and verification challenges) go through one client whose DNS lookup refuses link-local and cloud-metadata addresses always, and loopback and private ranges unless explicitly allowed. The check runs inside the connection's own lookup, so a DNS answer cannot be rebound between check and connect. IP literals are checked directly. |
| Blast radius | Per-scan request budget, write budget, maximum duration, rate, burst settings, test window, exclusions and an error-streak stop condition, all re-applied with server-side hard ceilings. DELETE is never sent. Writes need the authorization's write switch **and** a person's per-endpoint opt-in, and use synthetic data on reserved `.invalid` addresses. One scan per project; a server-wide concurrency cap. |
| Demo lab | Public, with no account. A visitor can only pick an example id: hosts, URLs, headers and credentials are fixed on the server, and the target is a fresh practice API on a loopback port, closed after the run. The local-target exception applies only to projects the lab builds, which live in memory apart from real data; no request can set it. Two concurrent runs per server, 20 starts per IP per 15 minutes, and a separate cap so visitors can't use up the slots for real scans. `BREAKAPI_LAB=false` turns it off. |
| Lab playground | Optional, on when `BREAKAPI_SIM_URL` and `BREAKAPI_SIM_CONTROL_KEY` are set. A visitor picks a preset or catalog ids, which are validated against the sim's catalog; unknown ids are refused. The sandbox address is built from `BREAKAPI_SIM_URL`, never from the request or from the sim's answer. The proof-of-control exemption covers only that one configured host, and only for in-memory lab projects (`isSimEntry` in `src/scope.js`). Playground projects get no loopback exemption and authorize no writes. The control key travels only over https (enforced at startup for hosted servers), is never returned to a visitor, and the client does not follow redirects, so a redirect cannot carry the key elsewhere. A server-wide daily cap (`BREAKAPI_LAB_DAILY_RUNS`) bounds the traffic the lab can send. |
| Embedded simulation | With `BREAKAPI_SIM_EMBED_DIR`, the sim runs inside this process on a random loopback port, with a control key generated at every boot and never stored or shown. Only `/sim/` and `/sim/s/<id>/…` are forwarded to it; `/sim/_control` and the rest are not reachable from outside. The pinned host is then this server's own address, so the exemption covers only the in-memory lab projects the server builds, and the scanner's root-level probes (`/.env` and similar) hit breakAPI itself and get a 404. |
| Hosted defaults | Production, an https `BREAKAPI_PUBLIC_URL` or a Replit instance makes the server *hosted*. Hosted servers refuse local and private targets unless explicitly allowed, even in development mode, and log a warning if allowed. |
| Traceability | Every request carries `X-BreakAPI-Scan: <id>` and a descriptive User-Agent; project audit logs record each decision with the acting user. |

## Review notes (October 2026)

Findings from the security review of the single-operator version, and how each was addressed:

1. **Shared access token as the only credential, used directly as the cookie value; no expiry or revocation.** → Replaced by user accounts and server-side sessions (above).
2. **No sign-in throttling.** → Per-IP and per-account rate limits with audit of failures.
3. **SSRF when hosted:** "localhost is exempt from verification" would let any user of a shared server scan the server and its private network; the verification fetch itself could reach internal hosts; DNS rebinding could bypass a check-then-fetch. → Local/private targets refused by default in production; one guarded client with in-lookup address checks for both scans and verification; metadata/link-local always refused.
4. **Prototype pollution** via `resourceIds` keys such as `__proto__`. → Reviver drops the keys; resource IDs are stored on a null-prototype object with key validation.
5. **Cookies not `Secure` behind HTTPS; no HSTS.** → `Secure` and HSTS when the public URL is HTTPS (or the trusted proxy says so).
6. **Encryption key stored next to the data it protects.** → `BREAKAPI_SECRET_KEY` from the environment in production.
7. **Authorizer identity unverified.** → Emailed confirmation by the authorizer; verified email for the test runner.
8. **No isolation between users.** → Project membership enforced on every project, scan and report route.
9. **Unbounded resource use** (endpoint counts, accounts, exclusion length, concurrent scans). → Caps added.
10. **Host-header-derived links** (password-reset poisoning risk). → Links are built from `BREAKAPI_PUBLIC_URL`, which production requires.

## Residual risks

- Email-based identity proves control of an inbox, not authority over the systems; the undertaking is a self-declaration. Neither replaces a written agreement with the system owner. Get legal advice.
- The data store is a single JSON file; a compromised host exposes findings (passwords and tokens are hashed, credentials encrypted).
- Rate limits are per process and reset on restart.
- An admin chooses or sees each issued password and token, and shares them outside the app. Until the user changes the password, the admin could sign in as them, which weakens the audit trail. Share details privately and don't send both over the same channel.
- Anyone with a demo lab run link can read that run until it is removed. Runs only contain fake data.
- On hosts without persistent storage (such as Replit Autoscale), accounts and audit logs can vanish when an instance is replaced.
- No multi-factor authentication yet. Admin accounts are the highest-value target; use long unique passwords.
- Session cookies are bearer credentials; anyone who steals one (e.g. through malware on the user's machine) can act as that user until it expires or is revoked.
- Verification challenges can be defeated where a third party controls the target's DNS or hosting (shared hosting, CDN misconfiguration, subdomain takeover).

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue. On GitHub, open the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability reporting; the repository owner enables it under *Settings → Code security*). Include steps to reproduce. Do not test against deployments you do not own.

The deliberately vulnerable practice API in `demo/` is not a vulnerability: it exists to be scanned, and binds to loopback only. The same goes for the planted flaws in the separate `breakapi-sim` repo; flaws in its control API or sandbox isolation are in scope.
