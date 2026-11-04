# breakAPI

**How secure is your API?**

breakAPI checks APIs you own, or are authorized to test, for common security weaknesses: broken access control, authentication gaps, cross-account data exposure (IDOR/BOLA), unsafe input handling, misconfiguration and missing rate limits.

**No test runs until the owner or an authorized representative records consent and the target is in the approved scope.**

> This is a testing demo application only.

## Two ways to use it

| | Demo lab | Real APIs |
| --- | --- | --- |
| **Who** | Anyone, no account | Accounts issued by an administrator |
| **Target** | A built-in practice API, chosen by the server | APIs you own or are authorized to test, after proving control |
| **How long** | Runs are kept for an hour | 30 days at most, ending sooner if the app restarts |
| **Guide** | [EXAMPLES.md](EXAMPLES.md) | [EXAMPLES.md](EXAMPLES.md#testing-a-real-api) |

## Quick start

Requires Node.js 22 or later. There are no dependencies to install.

```bash
npm start            # breakAPI on http://127.0.0.1:7300; prints a one-time setup token for the first admin
npm run demo         # optional: a deliberately vulnerable API on http://localhost:4010
npm test             # end-to-end tests
npm run admin -- list-users   # operator CLI: create-admin, reset-password, list-users, gen-key
```

Open the printed URL and choose **Try the demo lab**, or choose **Admin login**, paste the setup token and create the first administrator. Issue accounts for other people from **Admin**. In development, emails (password reset, authorizer confirmations) are written to `data/outbox/` instead of being sent.

**Putting it online?** [DEPLOY-REPLIT.md](DEPLOY-REPLIT.md) covers Replit, which runs the whole app.

**Deploying for other people?** Read [DEPLOY.md](DEPLOY.md) (Docker Compose with HTTPS, required settings, backups) and [SECURITY.md](SECURITY.md) (accounts, isolation, SSRF protection, residual risks).

To set up a project by hand against the practice API:

1. Run `npm run demo` and copy the two test tokens it prints (alice = id 1, bob = id 2).
2. Run `npm start`, open the printed URL, create the first administrator with the setup token, and create a project.
3. **Authorization:** record yourself as the owner, add `localhost:4010` as a host in scope, and confirm the attestations.
4. **Target:** import `demo/openapi.json` (the base URL is filled in from the spec).
5. **Test accounts:** add `alice` with resource `id=1` and `bob` with `id=2`.
6. **Scans:** start a scan, then open the report. After you fix something, click **Retest** to compare.

Or run `node testdata/seed.mjs --scan` with both servers up to get a configured project and a running scan in one step.

Test data lives in [`testdata/`](testdata/). The demo has switches for trying features by hand (`DEMO_FIXED=1`, `DEMO_RATE_LIMIT=5`, `DEMO_VERIFY_TOKEN`, `DEMO_HOST=0.0.0.0`).

Keyboard: <kbd>0</kbd>–<kbd>4</kbd> switch project sections, <kbd>j</kbd>/<kbd>k</kbd> move through findings, <kbd>s</kbd> start, <kbd>p</kbd> pause, <kbd>x</kbd> stop, <kbd>r</kbd> retest, <kbd>o</kbd> report, <kbd>?</kbd> all keys.

## How a scan stays safe

All network traffic goes through one guarded client ([src/client.js](src/client.js)). Each request is checked against the following before it is sent:

| Safeguard | Behavior |
| --- | --- |
| **Recorded consent** | Authorizer identity, basis (owner or delegated), three attestations, and an expiry of at most 90 days. Each new record supersedes the previous one; both are kept, and the record in force is snapshotted into every report. |
| **Legal undertaking** | The authorizer must accept a plain-language undertaking (responsibility for their testing, ownership or written permission, no third-party systems, synthetic data only, monitors informed) by ticking it and typing their full name. The accepted version, its hash, who, when and from where are recorded. The wording is a draft in [src/undertaking.js](src/undertaking.js), shown with a notice that it is **not legal advice** and should be reviewed by counsel. |
| **Exact host scope** | Requests go only to hosts listed in the authorization. Wildcards are not accepted and redirects are not followed. |
| **Proof of control** | **Every** host in scope that isn't localhost must serve a per-authorization token at `/.well-known/breakapi-verification.txt` or publish it in a `_breakapi.<host>` DNS TXT record. A verification lasts 24 hours, belongs to one authorization, and is re-run before every scan (fail closed). Link-local and cloud-metadata addresses are never contacted. Localhost is exempt, labelled "local development only", and reports say no ownership proof was made. |
| **Methods** | GET, HEAD and OPTIONS by default. POST, PUT and PATCH need the authorization's write switch **and** a per-endpoint opt-in (never granted by an import), are counted against a write budget, and are sent with synthetic data. DELETE is never sent. |
| **Limits** | Request budget, write budget, maximum scan duration, requests per second, separate burst settings for the rate-limit check, timeout, test window, and path exclusions. Hard ceilings apply even if stored controls are edited. |
| **Stop conditions** | The scan halts after N consecutive 5xx responses or timeouts, or when the request budget or maximum duration is reached, the window closes, or the authorization expires or is revoked. The write budget skips further writes. |
| **Owner control** | Pause, resume and stop at any time. Revoking the authorization stops running scans immediately. |
| **Identifiable traffic** | Every request carries `X-BreakAPI-Scan: <id>` and a descriptive User-Agent. |
| **Credentials** | Encrypted with AES-256-GCM (key in `data/secret.key`) and masked in logs and evidence. They are deleted automatically when the authorization expires or is revoked, and can be deleted on demand. |
| **Accounts and access** | Email + password accounts with `admin` and `user` roles, scrypt hashing, rate-limited sign-in, server-side sessions and password reset. There is no public sign-up: administrators issue accounts, which need a password and setup token at every sign-in and last 30 days at most. Projects and their findings are visible only to project members. The person who runs tests must have a verified email; an authorizer who isn't them confirms from an emailed link. See [SECURITY.md](SECURITY.md). |

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

### What the consent process does **not** guarantee

breakAPI's consent steps reduce the chance of testing something you shouldn't. They are not foolproof, and they are not a legal safeguard.

- A verification challenge shows that someone could publish a token at a location on the target at one moment. It does not prove legal ownership or authority. A DNS record proves control of a name, not of a particular service or port, and shared hosting, CDNs, wildcard DNS and subdomain takeover can all defeat it.
- The accepted undertaking is a self-declaration. It does not establish that you are authorized and does not remove legal risk.
- Identity is checked by email only. The person running tests needs a verified account email, and an authorizer who isn't the test runner must confirm from a link sent to their address. That proves control of an inbox, not authority over the systems.
- Hosting and cloud providers, contracts, data-protection rules and computer-misuse laws can impose requirements that breakAPI does not check. breakAPI cannot tell whether data in a target is real.
- Scope, rate limits and stop conditions are enforced by breakAPI's own client, not by the target or the network in between.
- Get **legal advice before testing anything beyond your own local or development systems**, and have a lawyer review the undertaking text in [src/undertaking.js](src/undertaking.js) before you rely on it.

## Layout

```
src/server.js       HTTP API, auth, validation, retention sweep
src/scanner.js      orchestration, findings, retest comparison
src/client.js       the guarded HTTP client (scope, budget, pacing, stop/pause)
src/lab.js          the public demo lab: example definitions and runs
src/scope.js        preflight checks (consent, undertaking, expiry, scope, per-host verification, window)
src/undertaking.js  the undertaking text, legal notice and authorization limitations (edit with counsel)
src/verify.js       DNS / well-known challenge, link-local and metadata blocking
src/synthetic.js    synthetic identities and values (reserved .invalid addresses)
src/checks/*.js     one module per check category
src/importers.js    OpenAPI / Postman / manual import
src/report.js       printable HTML report
public/             single-page UI (no build step), self-hosted JetBrains Mono
testdata/           specs, collections, token + seed scripts
demo/               deliberately vulnerable practice API and its spec; the lab binds it to loopback only
test/               end-to-end, account, access and demo lab tests
```
