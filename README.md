# breakAPI

**How secure is your API?**

breakAPI checks APIs you own, or are authorized to test, for common security weaknesses: broken access control, authentication gaps, cross-account data exposure (IDOR/BOLA), unsafe input handling, misconfiguration and missing rate limits.

**No test runs until the owner or an authorized representative records consent and the target is in the approved scope.**

> This is a testing demo application only. It finds indicators of risk; it cannot prove an API is secure. Read [what the consent process does not guarantee](#what-the-consent-process-does-not-guarantee) before testing anything that isn't your own.

- Zero dependencies, no build step: Node.js 22 or later, a hand-written server and a vanilla JS single-page app.
- A **demo lab** anyone can try without an account: fixed examples, plus a **playground** where you choose which vulnerabilities to plant in a simulated SaaS API and see whether breakAPI finds them.
- A guarded scanner for **real APIs**, with recorded consent, proof of control, request budgets and a hard stop on anything out of scope.

## Contents

- [Two ways to use it](#two-ways-to-use-it)
- [Quick start](#quick-start)
- [The demo lab and the simulation](#the-demo-lab-and-the-simulation)
- [Deploying](#deploying)
- [Running on your own server](#running-on-your-own-server)
- [Configuration](#configuration)
- [How a scan stays safe](#how-a-scan-stays-safe)
- [Checks](#checks) · [Inputs](#inputs) · [Limitations](#limitations)
- [Security](#security) · [Layout](#layout)

## Two ways to use it

| | Demo lab | Real APIs |
| --- | --- | --- |
| **Who** | Anyone, no account | Accounts issued by an administrator (there is no public sign-up) |
| **Target** | A practice API or a simulation sandbox, chosen by the server | APIs you own or are authorized to test, after proving control |
| **How long** | Runs are kept for an hour | Access lasts 30 days at most, ending sooner if the app restarts |
| **Guide** | [EXAMPLES.md](EXAMPLES.md) | [EXAMPLES.md](EXAMPLES.md#testing-a-real-api) |

## Quick start

Requires Node.js 22 or later. There are no dependencies to install.

```bash
npm start            # breakAPI on http://127.0.0.1:7300; prints a one-time setup token for the first admin
npm run demo         # optional: a deliberately vulnerable API on http://localhost:4010
npm test             # the test suite
npm run admin -- list-users   # operator CLI: create-admin, reset-password, list-users, gen-key
```

Open the printed URL and choose **Try the demo lab**, or choose **Admin login**, paste the setup token and create the first administrator. Issue accounts for other people from **Admin**. In development, emails (password reset, authorizer confirmations) are written to `data/outbox/` instead of being sent.

To set up a project by hand against the practice API:

1. Run `npm run demo` and copy the two test tokens it prints (alice = id 1, bob = id 2).
2. Run `npm start`, open the printed URL, create the first administrator with the setup token, and create a project.
3. **Authorization:** record yourself as the owner, add `localhost:4010` as a host in scope, and confirm the attestations.
4. **Target:** import `demo/openapi.json` (the base URL is filled in from the spec).
5. **Test accounts:** add `alice` with resource `id=1` and `bob` with `id=2`.
6. **Scans:** start a scan, then open the report. After you fix something, click **Retest** to compare.

Or run `node testdata/seed.mjs --scan` with both servers up to get a configured project and a running scan in one step. Test data lives in [`testdata/`](testdata/). The demo API has switches for trying features by hand (`DEMO_FIXED=1`, `DEMO_RATE_LIMIT=5`, `DEMO_VERIFY_TOKEN`, `DEMO_HOST=0.0.0.0`).

Keyboard: <kbd>0</kbd>–<kbd>4</kbd> switch project sections, <kbd>j</kbd>/<kbd>k</kbd> move through findings, <kbd>s</kbd> start, <kbd>p</kbd> pause, <kbd>x</kbd> stop, <kbd>r</kbd> retest, <kbd>o</kbd> report, <kbd>?</kbd> all keys.

## The demo lab and the simulation

The lab never takes a target from a visitor: a request can only name an example or catalog ids, and the server builds everything else.

- **Examples.** Fixed scenarios against a deliberately vulnerable practice API that breakAPI starts on a loopback port for each run: one per kind of test, plus "safety" examples that show breakAPI's own limits (the consent wall, the request budget, write protection). See [EXAMPLES.md](EXAMPLES.md).
- **Simulation playground** (optional). A second project, **breakapi-sim**, runs "Northwind Docs", a small multi-tenant SaaS API (organizations, people in different roles, documents, comments, search, an admin area). Each run gets its own sandbox with the vulnerabilities you choose, planted or patched:

  | Planted flaw | Found by |
  | --- | --- |
  | Permissive CORS with credentials | Configuration |
  | Published API specification | Exposure |
  | Guessable JWT signing key; unsigned (`alg=none`) tokens | Authentication |
  | Documents readable across tenants (BOLA); admin routes open to every user (BFLA) | Authorization |
  | SQL error from the search string | Input handling |

  After the scan, a **planted vs detected** table shows what breakAPI found, missed, or reported when the flaw was patched (a false alarm). Change the flaws and **retest** the same sandbox to see findings move from open to fixed. Every record in a sandbox is fictional, and every flaw is simulated in code: there is no database and no outbound call.

The playground is on when breakAPI can reach a sim. Either run the sim as its own app and set `BREAKAPI_SIM_URL` and `BREAKAPI_SIM_CONTROL_KEY`, or clone the `breakapi-sim` repository into a folder and set `BREAKAPI_SIM_EMBED_DIR` to run it inside the same process. Without either, the lab shows only the examples.

## Deploying

| You want | Use |
| --- | --- |
| A free public demo, with the pages on Netlify and everything else in **one** Replit project | [DEPLOY-NETLIFY.md](DEPLOY-NETLIFY.md). It also covers Replit alone, without Netlify |
| breakAPI and the simulation as **two** Replit apps | [DEPLOY-REPLIT.md](DEPLOY-REPLIT.md) |
| A server you control, with persistent data and your own domain | [Running on your own server](#running-on-your-own-server), below |
| Just to try it | `npm start` on your own machine |

Replit's free workspace sleeps when idle and its data is disposable, so treat that setup as a demo. For anything people rely on, use a host with a persistent disk. Read [SECURITY.md](SECURITY.md) (accounts, isolation, SSRF protection, residual risks) before opening a server to other people.

**Hosted servers are locked down by default.** When breakAPI runs in production, behind an `https://` public URL, or on Replit, it refuses to scan `localhost`, private-network or cloud-metadata addresses unless you explicitly allow them.

## Running on your own server

Use this when you want data that persists and your own domain, instead of the free Replit demo. You need:
- a machine with Node.js 22 or later, a domain name, and a reverse proxy that terminates TLS (Caddy, nginx or a load balancer);
- an SMTP account for outbound email (production refuses to start without one);
- a legal review of the undertaking text in [src/undertaking.js](src/undertaking.js) before anyone relies on it.

```bash
cp .env.example .env
node src/cli.js gen-key        # or: openssl rand -base64 32 → BREAKAPI_SECRET_KEY
```

Fill in `.env`. With `BREAKAPI_ENV=production` the server refuses to start unless these are set:

| Variable | Why |
| --- | --- |
| `BREAKAPI_PUBLIC_URL` | The `https://` address users reach. Used for emailed links (never the request's Host header, so links can't be poisoned) and to mark cookies `Secure` |
| `BREAKAPI_SECRET_KEY` | 32-byte base64 key that encrypts stored test credentials. Keep it in your secret store, **not** next to the data. Losing or changing it makes stored credentials unreadable |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `BREAKAPI_MAIL_FROM` | Password-reset and authorizer-confirmation email. Port 465 uses implicit TLS, 587 uses STARTTLS. Credentials are never sent unencrypted to a remote host |

Then start it and put the proxy in front. Set `HOST=127.0.0.1` so the app can't be reached around the proxy, and `BREAKAPI_TRUST_PROXY=true` so it reads the visitor's IP and the HTTPS flag from the proxy:

```bash
BREAKAPI_ENV=production HOST=127.0.0.1 node --env-file=.env src/main.js
```

A minimal Caddy configuration (Caddy gets and renews the certificate itself):

```
breakapi.example.com {
	reverse_proxy 127.0.0.1:7300
}
```

Run breakAPI under a process manager (systemd, pm2 or similar) so it restarts on failure. The startup log prints a one-time **setup token**. Open `https://<your-domain>`, choose **Admin login**, paste it, and create the first administrator. The token is deleted once used.

To use the simulation playground, run the `breakapi-sim` app elsewhere and set `BREAKAPI_SIM_URL` and `BREAKAPI_SIM_CONTROL_KEY` in `.env`.

### Users and recovery

- **Issue accounts:** Admin → *Issue a user account*. You get a password and setup token to share privately, shown once. The user needs both at every sign-in. Access lasts 30 days at most and **ends when the app restarts**, so plan upgrades and tell users; *Issue again* gives them new details and a new 30 days.
- **Roles:** `admin` manages users and sees server settings and the system audit log. Admins do **not** automatically see other people's projects: projects are visible only to their members. Projects that were never assigned an owner appear under **Admin → Projects nobody owns**, where an admin can claim or delete them.
- <a id="recovery-without-email"></a>**Recovery without email:** stop the server, then
  ```bash
  node src/cli.js create-admin --email you@example.com --name "Your Name"   # creates or promotes, signs out everywhere
  node src/cli.js reset-password --email someone@example.com
  node src/cli.js list-users
  ```
  The password comes from `BREAKAPI_ADMIN_PASSWORD` or a prompt.

### Operating a server

- **Health:** `GET /healthz` and `GET /readyz` (`/readyz` writes the data file and returns 500 if the volume isn't writable). On Google-hosted platforms, which answer `/healthz` themselves, use `/api/healthz`.
- **Logs:** one JSON line per request on stdout (method, path without query string, status, duration, user id, IP). Secrets, cookies and request bodies are never logged.
- **Audit:** every project keeps its own audit log; the admin page shows the system audit log (sign-ins, failed sign-ins, role changes, disables, deletions).
- **Shutdown:** `SIGTERM` stops running scans (recorded as stopped with a reason), flushes the data file and exits. Scans interrupted by a crash are marked *interrupted* on the next start.
- **Backups:** back up the data volume (`db.json`). It holds hashed passwords, hashed tokens, encrypted test credentials and all findings, so treat backups as sensitive. Keep `BREAKAPI_SECRET_KEY` separately; without it the encrypted credentials in a backup are unreadable, by design.
- **Upgrades:** stop, replace the image or code, start. Data migrations run at startup. Issued access ends with the restart, so issue it again afterwards.

### Limits to know about

- **Single process, single file.** The data store is one JSON file written atomically. That suits a team-sized deployment; running more than one replica against the same volume will lose data. Move to a database before scaling horizontally.
- **Rate limits and lab runs are in memory** and reset on restart.
- **Email is the identity anchor.** Account verification and authorizer confirmation prove control of an inbox, not legal authority.
- **The practice API ships for the demo lab,** which binds it to loopback and closes it after each run. Never run `npm run demo` on a network-facing address.

## Configuration

Everything is an environment variable; `.env.example` lists them with comments.

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT`, `HOST` | `7300`, `127.0.0.1` (`0.0.0.0` in production) | Where breakAPI listens |
| `BREAKAPI_ENV` | `development` | `production` enforces the required settings above |
| `BREAKAPI_DATA` | `./data` | Data directory (`db.json`, setup token, generated key, outbox) |
| `BREAKAPI_PUBLIC_URL` | none | The address people use. Required in production |
| `BREAKAPI_SECRET_KEY` | generated file | Encrypts stored test credentials |
| `BREAKAPI_TRUST_PROXY` | `false` | Read client IP and HTTPS flag from `X-Forwarded-*`. Only behind a proxy the app can't be reached around |
| `BREAKAPI_ALLOW_LOCAL_TARGETS` | `true` on a laptop, `false` when hosted | `true` would let users scan the server itself |
| `BREAKAPI_ALLOW_PRIVATE_TARGETS` | `true` on a laptop, `false` when hosted | `true` would let users reach `10.x`, `172.16–31.x`, `192.168.x`. Link-local and cloud-metadata addresses are **always** refused |
| `BREAKAPI_LAB` | `true` | The public demo lab. `false` removes it |
| `BREAKAPI_LAB_DAILY_RUNS` | `300` | Server-wide cap on lab runs per UTC day |
| `BREAKAPI_SIM_URL`, `BREAKAPI_SIM_CONTROL_KEY` | none | A separately hosted simulation. Set both or neither; https only when hosted |
| `BREAKAPI_SIM_EMBED_DIR`, `BREAKAPI_SIM_PUBLIC_URL` | none | A simulation checkout run inside this process, and the address the scanner reaches this server on |
| `BREAKAPI_MAX_CONCURRENT_SCANS` | `4` | Server-wide cap on running scans |
| `BREAKAPI_SESSION_HOURS` | `12` | Admin idle timeout. Admin sessions also end 7 days after sign-in |
| `SMTP_*`, `BREAKAPI_MAIL_FROM` | none | Outbound email; required in production |

## How a scan stays safe

All network traffic goes through one guarded client ([src/client.js](src/client.js)). Each request is checked against the following before it is sent:

| Safeguard | Behavior |
| --- | --- |
| **Recorded consent** | Authorizer identity, basis (owner or delegated), three attestations, and an expiry of at most 90 days. Each new record supersedes the previous one; both are kept, and the record in force is snapshotted into every report |
| **Legal undertaking** | The authorizer must accept a plain-language undertaking (responsibility for their testing, ownership or written permission, no third-party systems, synthetic data only, monitors informed) by ticking it and typing their full name. The accepted version, its hash, who, when and from where are recorded. The wording is a draft in [src/undertaking.js](src/undertaking.js), shown with a notice that it is **not legal advice** and should be reviewed by counsel |
| **Exact host scope** | Requests go only to hosts listed in the authorization. Wildcards are not accepted and redirects are not followed |
| **Proof of control** | **Every** host in scope that isn't localhost must serve a per-authorization token at `/.well-known/breakapi-verification.txt` or publish it in a `_breakapi.<host>` DNS TXT record. A verification lasts 24 hours, belongs to one authorization, and is re-run before every scan (fail closed). Link-local and cloud-metadata addresses are never contacted. Localhost is exempt, labelled "local development only", and reports say no ownership proof was made |
| **Methods** | GET, HEAD and OPTIONS by default. POST, PUT and PATCH need the authorization's write switch **and** a per-endpoint opt-in (never granted by an import), are counted against a write budget, and are sent with synthetic data. DELETE is never sent |
| **Limits** | Request budget, write budget, maximum scan duration, requests per second, separate burst settings for the rate-limit check, timeout, test window, and path exclusions. Hard ceilings apply even if stored controls are edited |
| **Stop conditions** | The scan halts after N consecutive 5xx responses or timeouts, or when the request budget or maximum duration is reached, the window closes, or the authorization expires or is revoked. The write budget skips further writes |
| **Owner control** | Pause, resume and stop at any time. Revoking the authorization stops running scans immediately |
| **Identifiable traffic** | Every request carries `X-BreakAPI-Scan: <id>` and a descriptive User-Agent |
| **Credentials** | Encrypted with AES-256-GCM and masked in logs and evidence. Deleted automatically when the authorization expires or is revoked, and can be deleted on demand |
| **Accounts and access** | Email + password accounts with `admin` and `user` roles, scrypt hashing, rate-limited sign-in, server-side sessions and password reset. No public sign-up. Projects and their findings are visible only to project members. The person who runs tests must have a verified email; an authorizer who isn't them confirms from an emailed link |

## Checks

| Category | What it does |
| --- | --- |
| Configuration | Plain HTTP, missing HSTS, CORS origin reflection with or without credentials, the `null` origin, technology disclosure, missing `nosniff`, cacheable authenticated responses |
| Exposure | Signature-confirmed GETs for `.env`, `.git`, actuator/pprof/expvar, server-status, phpinfo, `config.json`, and published API specs |
| Authentication | Anonymous access to endpoints that require auth, invalid credentials accepted. JWT: `alg: none`, unverified signature, signing secret found in a weak-secret wordlist (checked offline), missing or long expiry |
| Authorization | Cross-account object access: account B requests account A's resource IDs, and the response is compared with A's view and with B's own. Admin-only endpoints reachable by regular users. Sequential IDs (informational) |
| Input handling | A stray quote (SQL error signatures), an inert reflected marker in HTML, path traversal, and non-numeric values for numeric parameters. Read-only GETs only |
| Data validation *(synthetic writes)* | Malformed emails, wrong types and implausible numbers accepted by the server; privileged fields settable by the client (mass assignment) |
| Identity & accounts *(synthetic writes)* | A session issued before email verification, case-variant duplicate emails, trivially weak passwords, login responses that reveal whether an account exists; session cookie flags |
| Business logic *(synthetic writes)* | Negative or unbounded quantities, client-controlled prices and amounts, identical requests creating duplicates (bounded and sequential: no race-condition flooding) |
| Rate limiting | A bounded burst against an auth-like or authenticated endpoint, looking for HTTP 429 or rate-limit headers |
| Passive | Stack traces or debug output; cookie flags; data-quality indicators in responses already fetched (malformed emails, implausible ages and dates, negative counts, `updatedAt` before `createdAt`): low-confidence, for human review |

You can fix a finding and rerun the scan: the retest reports each previous finding as fixed, still open or new. Previous findings whose check did not complete in the retest are listed as *not re-verified*.

## Inputs

- **OpenAPI 3 / Swagger 2 (JSON):** `$ref` parameters and schemas, and security requirements (to decide whether an endpoint requires auth). Operations tagged `admin`, or marked with `x-breakapi-admin: true`, are treated as admin-only. YAML must be converted to JSON first.
- **Postman collection v2:** `{{baseUrl}}` and `:param` placeholders, and `noauth` items.
- **Manual list:** `GET /users/{id}`, with optional `public` or `admin` flags, one per line.

## Limitations

- breakAPI identifies indicators of risk. It cannot prove an API is secure or find every vulnerability.
- Results depend on the accuracy of the spec, test accounts, roles and resource IDs you supply.
- Some findings need human review and may be false positives. Subtle, business-logic and multi-step flaws are out of scope.
- Rate limits that only trigger above the configured burst size will not be detected.

### What the consent process does not guarantee

breakAPI's consent steps reduce the chance of testing something you shouldn't. They are not foolproof, and they are not a legal safeguard.

- A verification challenge shows that someone could publish a token at a location on the target at one moment. It does not prove legal ownership or authority. A DNS record proves control of a name, not of a particular service or port, and shared hosting, CDNs, wildcard DNS and subdomain takeover can all defeat it.
- The accepted undertaking is a self-declaration. It does not establish that you are authorized and does not remove legal risk.
- Identity is checked by email only. That proves control of an inbox, not authority over the systems.
- Hosting and cloud providers, contracts, data-protection rules and computer-misuse laws can impose requirements that breakAPI does not check. breakAPI cannot tell whether data in a target is real.
- Scope, rate limits and stop conditions are enforced by breakAPI's own client, not by the target or the network in between.
- Get **legal advice before testing anything beyond your own local or development systems**, and have a lawyer review the undertaking text in [src/undertaking.js](src/undertaking.js) before you rely on it.

## Security

[SECURITY.md](SECURITY.md) describes the security model (accounts, isolation, SSRF protection, the demo lab and simulation trust boundaries) and the residual risks. To report a vulnerability in breakAPI, follow the instructions there. The deliberately vulnerable practice API in `demo/` and the planted flaws in the simulation are not vulnerabilities: they exist to be scanned.

## Layout

```
src/server.js       HTTP API, auth, validation, retention sweep
src/scanner.js      orchestration, findings, retest comparison
src/client.js       the guarded HTTP client (scope, budget, pacing, stop/pause)
src/netguard.js     SSRF protection: address classes, DNS lookup checked at connect time
src/lab.js          the public demo lab: examples, playground runs, retests
src/labscore.js     planted-vs-detected scoring for playground runs
src/simclient.js    client for the simulation's control API
src/simembed.js     runs a breakapi-sim checkout inside this process
src/scope.js        preflight checks (consent, undertaking, expiry, scope, per-host verification, window)
src/undertaking.js  the undertaking text, legal notice and authorization limitations (edit with counsel)
src/verify.js       DNS / well-known challenge
src/synthetic.js    synthetic identities and values (reserved .invalid addresses)
src/checks/*.js     one module per check category
src/importers.js    OpenAPI / Postman / manual import
src/report.js       printable HTML report
public/             single-page UI (no build step), self-hosted JetBrains Mono
demo/               deliberately vulnerable practice API and its spec; the lab binds it to loopback only
deploy/             Netlify build script
testdata/           specs, collections, token + seed scripts
test/               end-to-end, account, access, lab and simulation-contract tests
```

The simulation backend lives in its own repository, **breakapi-sim**. `npm test` includes contract tests that run breakAPI's scanner against it when it is checked out next to this repo (`../breakAPI-sim`, or the folder in `BREAKAPI_SIM_DIR`), and skip otherwise.
