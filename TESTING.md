# Testing breakAPI end to end

This guide walks through every feature using the bundled vulnerable demo API and the data in [`testdata/`](testdata/). Each step says what to do and what you should see. Allow about an hour for the whole run. The "Fast path" below gets you to a finished scan in two minutes.

> The demo API in `demo/` is deliberately insecure. Run it only on your own machine and never expose it to a network. To see breakAPI work without any setup, use the demo lab instead: [EXAMPLES.md](EXAMPLES.md).

## Host and base URL: the most common first stumble

| Field | Value for the demo | Rules |
| --- | --- | --- |
| **Hosts in scope** (Authorization tab) | `localhost:4010` | One per line. `host` or `host:port` only: no `http://`, no path, no wildcards. IPv6 needs brackets: `[::1]:4010` |
| **Base URL** (Target tab) | `http://localhost:4010` | A full URL with scheme. Its host must be one of the hosts in scope |

`0:0:0:0:4010` is not valid (colons are separators); write `localhost:4010`. Avoid `0.0.0.0:4010` for the plain demo: it is not treated as local, so you would be asked to verify it. (It is useful in §5, where we *want* a non-local host that can pass the challenge.)

## What's in `testdata/`

| File | Used for |
| --- | --- |
| [`demo/openapi.json`](demo/openapi.json) | OpenAPI 3 spec of the demo API (14 operations, including a DELETE that must never be called) |
| [`testdata/demo-postman.json`](testdata/demo-postman.json) | The original read/PATCH part of the API as a Postman v2.1 collection |
| [`testdata/demo-manual.txt`](testdata/demo-manual.txt) | The same, as a manual endpoint list |
| [`testdata/invalid-spec.yaml`](testdata/invalid-spec.yaml) | A YAML spec, which the import should reject with a clear message |
| [`testdata/not-a-spec.json`](testdata/not-a-spec.json) | Valid JSON that isn't a spec, which the import should reject |
| [`testdata/tokens.mjs`](testdata/tokens.mjs) | Prints fresh test tokens for alice, bob and root (valid for 24 hours) |
| [`testdata/seed.mjs`](testdata/seed.mjs) | Creates a fully configured project through the API. `--writes` also authorizes write requests and opts the demo's signup, login and order endpoints in; `--scan` starts a scan |

### Demo API switches

Set these environment variables when you start the demo:

| Variable | Effect |
| --- | --- |
| `PORT=4010` | Port (default 4010) |
| `DEMO_HOST=0.0.0.0` | Listen on every network interface. Needed for the non-local verification test (§5) |
| `DEMO_FIXED=1` | Patches the cross-account reads, the missing login on invoices, the admin check, `alg: none` tokens, CORS, and every weakness the synthetic checks look for: signup validation, mass assignment, session-before-verification, email normalization, password rules, login enumeration, order quantity and price, replays, cookie flags and the inconsistent stored data. Used to see "fixed" results on a retest (§11) |
| `DEMO_RATE_LIMIT=5` | Answers `429` after 5 requests per second per client (§11) |
| `DEMO_VERIFY_TOKEN=<token>` | Serves `<token>` at `/.well-known/breakapi-verification.txt` (§5) |

### Test accounts

Run `node testdata/tokens.mjs` to print fresh tokens. Add `--json` for JSON output.

| Label | Role | Resources it owns (one per line as `param=value`) | Use |
| --- | --- | --- | --- |
| alice | user | `id=1` and `email=alice@demo.test` | primary account; the `email` is how the login-enumeration check knows a real address |
| bob | user | `id=2` and `email=bob@demo.test` | second account, for cross-account checks |
| root | admin | `id=3` | admin account. It is never used as the attacker or for synthetic writes |

## 0. Start everything

You need three terminals.

```bash
# terminal 1 — the demo target
npm run demo

# terminal 2 — breakAPI (development mode: email goes to data/outbox/ instead of being sent)
npm start          # prints the setup URL and a one-time setup token

# terminal 3 — helpers
node testdata/tokens.mjs
```

**Reading "emails" locally:** with no SMTP configured, every email is written to `data/outbox/*.eml` and its path is printed in terminal 2. Open the newest file and copy the link (for example `http://localhost:7300/#/verify/…`).

**Fast path (optional):** with both servers running, `node testdata/seed.mjs --scan` creates the first administrator if none exists (**dana@example.com / demo-passphrase-change-me**), then a project "Demo API — local" with a self-recorded authorization (including the undertaking), the endpoints, alice and bob, and safety controls, and starts a read-only scan. Add `--writes` for the full run with synthetic writes (§12). On a server that already has users, pass `--email` and `--password` (or `BREAKAPI_EMAIL` / `BREAKAPI_PASSWORD`).

## 1. Accounts, sign-in and roles

### First administrator

| Step | Expected |
| --- | --- |
| Open `http://localhost:7300/` on a fresh data directory | The **Create the first administrator** page. No other page is reachable yet |
| Enter a wrong setup token | "That setup token is not correct…" |
| Enter the token from terminal 2, your name, `dana@example.com`, and the password `short` | "Use at least 12 characters." |
| Use a 12+ character password | You're signed in as an admin; the prompt reads `dana@breakapi:~/projects$`; **Admin** and **Account** appear top right. `data/setup-token` is gone |
| Restart breakAPI | No setup token is printed any more |

### Sign-in, sessions and lockout

| Step | Expected |
| --- | --- |
| **Sign out**, then sign in with a wrong password | "Email or password is incorrect, or the account is not active." |
| Sign in with an address that has no account | Exactly the same message (no account enumeration) |
| Fail nine times in a row for one address | "Too many attempts. Try again in N minute(s)." (HTTP 429 with `Retry-After`) |
| Sign in correctly in two browsers, then **Account → Sessions** | Two rows, one marked **this session** |
| **Account → Change password** in browser A | Browser A stays signed in; browser B is signed out on its next action |
| **Account → Sign out everywhere** | Back at the sign-in page; the other browser is signed out too |
| `curl -i http://127.0.0.1:7300/api/projects` | `401 Sign in required` |
| Sign in, copy the `bp_sid` cookie, then `curl -i -X POST -b "bp_sid=<value>" http://127.0.0.1:7300/api/projects` | `403 Missing X-BreakAPI header` (CSRF protection) |
| The same with `-H "x-breakapi: 1" -H "origin: https://evil.example"` | `403 Cross-origin request refused` |
| `curl -sI http://127.0.0.1:7300/ \| grep -i content-security` | A strict CSP: `default-src 'self'; object-src 'none'…` |

### Forgot password

| Step | Expected |
| --- | --- |
| Sign out → **Forgot your password?** → enter an unknown address | "If an account exists for that address, a reset link is on its way." No email is written |
| Do it for `dana@example.com` | Same message; a new `.eml` in `data/outbox` with a `/#/reset/…` link |
| Open the link, set a new password | "Password changed"; all of Dana's sessions end. The link doesn't work a second time |

### Issuing a user account, and what users can't do

| Do | Expect |
| --- | --- |
| **Admin → Issue a user account**: `uma@example.com`, name `Uma`, password blank | A **Share these details** panel at the top of the page shows a generated password and setup token, once. Nothing is emailed |
| In a private window, choose **User login** and enter the email and password with a wrong setup token | "Those details aren't right…", the same message as a wrong password |
| Enter the right setup token | Signed in as Uma, email **verified**. **Account** shows when access ends |
| Open `/#/admin` as Uma | "Administrators only." The Admin button isn't shown |
| Sign in as Uma in a second browser | The first browser's session ends: one session at a time |
| Restart breakAPI, then sign in as Uma | "Your access ended when the app restarted." Dana's admin account still works |
| **Admin → Users → Issue again** on Uma | New password and setup token. The old ones stop working, and access runs for another 30 days |
| Change Uma's role to `admin` | Uma is signed out, and signs in again from **Admin login** with no token or time limit |

## 2. Projects

| Step | Expected |
| --- | --- |
| Press <kbd>n</kbd>, type `Demo API — local`, then **Create project** | Opens **0:authorization**. Sections that still need work are marked `!` in the green bar |
| Press <kbd>?</kbd> | The keyboard reference opens. <kbd>Esc</kbd> closes it |
| Press <kbd>u</kbd> | Back to the project list. The project shows **Authorization: none** |

## 3. Authorization, undertaking and scope

Open the project. With no authorization yet it opens on **0:authorization**, a form in three steps: *who authorizes this test*, *what may be tested and until when* (read-only checks and fake-data checks in two groups, each with a line saying what it sends), and *accept the undertaking* (with *What this does not prove* shown before you accept). The undertaking is a plain-language draft with a notice that it is not legal advice. Once a project is ready it opens on **4:scans** instead, and the header always shows a **next:** step.

**Validation.** Each of these should be refused with the message shown:

| Input | Expected message |
| --- | --- |
| Leave the undertaking box unchecked or the name empty | The browser blocks the submit and marks the field (required) |
| Tick the undertaking but type a different name (e.g. `Someone Else`) | "Type the authorizer’s full name exactly as entered above to accept the undertaking." |
| Email `dana@` | "A valid authorizer email is required." |
| Host `*.example.com` | "…is not a valid host… no scheme, path or wildcards." |
| Host `http://localhost:4010` or `0:0:0:0:4010` | The same host error |
| Expiry 120 days from now | "Authorizations can last at most 90 days." |
| Expiry in the past | "Expiry must be in the future." |
| Choose **The owner has delegated authority to me**, leave details empty | "Describe the delegated authority…" |
| Uncheck every test | "Authorize at least one test category." |

**Record a valid authorization:**

- Name `Dana Ruiz`, email `dana@example.com`, role `API owner`
- Expiry: the default (7 days)
- Why they may authorize it: they own this API
- Hosts: `localhost:4010`
- All nine tests checked; write requests **unchecked** (for now)
- In step 3, read *What this does not prove*, tick the undertaking and type `Dana Ruiz` (capitalization and extra spaces don't matter) → **Record authorization**

Expected:
- "Current authorization" shows **active**, with an **Undertaking** row (accepted by Dana Ruiz, with a version).
- The audit log shows `undertaking.accepted` and `authorization.recorded`.
- The `!` disappears from `0:authorization`.

Once recorded, the form collapses behind **Replace authorization**; the audit log and history are collapsed too (click to open). Errors from any form also appear inside the form, above its button.

**History:** click **Replace authorization** and record it again with role `CTO`. An **Authorization history** table appears with the previous record and its *Ended* time. Because verification belongs to one authorization, any verified host needs verifying again after a new record (§5).

**When the authorizer is someone else.** breakAPI verifies the *test runner* (your signed-in, verified account) and makes the *authorizer* confirm for themselves.

| Step | Expected |
| --- | --- |
| In a second project, change **Authorizer email** to `olu@example.com` and the name to `Olu Owner` | The undertaking section disappears and a note says we'll email olu@example.com; the button reads **Record and email the authorizer** |
| Record it | "Recorded. We emailed olu@example.com to confirm." The authorization shows **awaiting confirmation**; pre-flight says "Waiting for olu@example.com to confirm…"; **Start scan** is disabled |
| Open the `/#/confirm/…` link from the newest outbox email **in a private window** (no breakAPI account needed) | **Authorize security testing**: who recorded it, the hosts, tests, write setting, expiry, "What this does not prove", the undertaking and its legal notice |
| Tick the box but type `Dana Ruiz` | "Type your full name (Olu Owner) to accept the undertaking." |
| Type `Olu Owner` → **Confirm authorization** | "The authorization is confirmed." Back in Dana's window the authorization is **active**, *Confirmed* reads "link emailed to olu@example.com", and scans can start |
| Open the same link again | "This confirmation link is invalid, already used, expired or replaced…" |
| Record a new delegated authorization, click **Resend the email**, then open the *first* link | Invalid: resending replaces the old link |
| Open the newest link and click **Decline** (confirm in the dialog) | "You declined." The authorization shows **declined** |
| Run a scan on a confirmed project and open its report | The report header says **Started by Dana Ruiz** with her verification time; AUTHORIZATION lists *Recorded … by dana@example.com* and *Confirmed … link emailed to olu@example.com* |

## 4. Target and endpoint import

Open **1:target** (or press <kbd>1</kbd>).

| Step | Expected |
| --- | --- |
| Base URL `ftp://localhost:4010` | "Base URL must use http or https." |
| Base URL `http://user:pw@localhost:4010` | "Do not put credentials in the base URL…" |
| Import `testdata/invalid-spec.yaml` (format OpenAPI) | "…YAML is not supported yet — convert it first…" |
| Import `testdata/not-a-spec.json` | "Not an OpenAPI/Swagger document…" |
| Import `testdata/demo-manual.txt` (choosing the file switches the format to Manual) | "Imported 8 endpoints". `/api/health` has **Needs login** off; `/api/admin/users` has **Admin only** on |
| Import `testdata/demo-postman.json` | Merges with the list, with no duplicates. Adds `PATCH /api/users/{id}` |
| Import `demo/openapi.json` with **Replace the existing endpoints** checked | Exactly 14 endpoints, including `DELETE /api/users/{id}`. The base URL fills in as `http://localhost:4010` from the spec |
| Look at the **Fake-data writes** column | Every POST/PATCH row (`/api/login`, `/api/users`, `/api/orders`, `PATCH /api/users/{id}`) shows an **unticked, disabled** checkbox with its detected kind (`login`, `signup`, `order`, `profile`). Importing never ticks it |
| Untick **Test** on one endpoint, then tick it again | A "Saved" toast each time; the change survives a page reload |

## 5. Verifying control of each host

For localhost there is nothing to verify: the Target tab says every host is local, and the report will state "Local development only — no ownership proof was made". To test the real flow you need a host that is **not** local but reachable. On your own machine, `0.0.0.0` is exactly that: it isn't classed as loopback, but connects to this machine.

1. On **0:authorization**, record a new authorization (undertaking again) with hosts `localhost:4010`, `0.0.0.0:4010` and `blocked.invalid`. The last name never resolves; it plays an unverifiable second host.
2. On **1:target**, set the base URL to `http://0.0.0.0:4010`. The **Verify control of each host** panel shows this authorization's token (`breakapi-verify-…`), plus two rows that need checking (`0.0.0.0:4010`, `blocked.invalid`) and `localhost:4010` as **local only**.
3. Press <kbd>4</kbd> (scans). Pre-flight lists `[ FAIL ] Control of "0.0.0.0:4010" is not verified…` and the same for `blocked.invalid`. **Start scan** is disabled.
4. Click **Check** on `0.0.0.0:4010`. Expected: "Token not found at http://0.0.0.0:4010/.well-known/breakapi-verification.txt or…"
5. Restart the demo so it serves the token (copy it from the panel):
   ```bash
   DEMO_HOST=0.0.0.0 DEMO_VERIFY_TOKEN=<paste token> npm run demo
   ```
6. **Check** on `0.0.0.0:4010` again → **verified**, method `well-known file`; audit shows `host.verified`.
7. Pre-flight still blocks because of `blocked.invalid`. Click **Check** on it → an error (it can't be reached). That is the point: *every* non-local host in scope must be verified, not just the base URL's.
8. Record the authorization again with only `0.0.0.0:4010` (and `localhost:4010`). Its token changes and the host shows **not verified** again: verification belongs to one authorization.
9. Put the new token in the demo, **Check** again, then start a scan. It runs, because the challenge is **re-run immediately before every scan** and fails closed.
10. Stop the demo's token (restart it with `DEMO_VERIFY_TOKEN=wrong`) and start another scan: **422 "Scan blocked: re-verification of "0.0.0.0:4010" failed."**
11. Verification also expires 24 hours after it was checked ("expired" in the table). You can't wait a day, so trust the automated test for that rule (§15).
12. Link-local and cloud-metadata addresses are never contacted: record an authorization with host `169.254.169.254` and click **Check**. Expected: "…resolves to a link-local or cloud-metadata address, which breakAPI never contacts."
13. Afterwards, restore the authorization to `localhost:4010` with base URL `http://localhost:4010` and run the demo plainly.

## 6. Test accounts

Open **2:accounts**. Use the tokens from `node testdata/tokens.mjs`.

| Step | Expected |
| --- | --- |
| Add `alice`, Regular user, Bearer, alice's token, owns `id=1` and `email=alice@demo.test` (two lines) | The row shows the credential masked (`eyJh••••xx`) and both resources |
| Add `bob`, Regular user, Bearer, bob's token, owns `id=2` and `email=bob@demo.test` | Second row |
| Add another account called `alice` | "Account labels must be unique." |
| Add `key-test`, API key in a custom header, header name empty | "Header name is required for header authentication." |
| Add `key-test` with header `X-API-Key`, any value, then **Remove** it | It is added and then removed (audit: `account.added`, `account.deleted`) |
| *(optional)* Add `root`, Admin, root's token, `id=3` | Admin accounts are never used as the attacker or for synthetic writes |

Credentials never appear in plain text afterwards (nor do session ids or link tokens, which are stored hashed). To confirm: `grep -c "$(node testdata/tokens.mjs | sed -n 2p | tr -d ' ' | cut -d. -f3)" data/db.json` prints `0`.

## 7. Safety controls

Open **3:controls**.

| Step | Expected |
| --- | --- |
| Set **Request budget** `5` and save | Clamped to `10` (the minimum). Values are clamped, not rejected |
| Set **Request rate** `20`, **Burst rate** `50`, **Rate-limit burst** `30`, save | Saved. A fast, still bounded scan |
| Check the new fields **Write budget** (default 50) and **Max duration** (default 30 minutes) | Present. Write budget accepts 0–500; duration 1–120 minutes |
| Set **Window opens** to tomorrow, save, go to **4:scans** | Pre-flight shows `[ FAIL ] Test window has not started…` and **Start scan** is disabled |
| Clear the window and save | The pre-flight is back to `[  OK  ]` lines |
| Add exclusion `/api/admin/*` and monitoring contact `dana@example.com` | Saved. Keep the exclusion for §8, then remove it in §10 |

## 8. Run a scan (read-only)

Open **4:scans**. Pre-flight should list three `[  OK  ]` lines. Press <kbd>s</kbd> or click **Start scan**.

While the scan runs:
- The header shows `running`.
- The segmented bar fills, and check names gain `ok` as each finishes.
- The severity tally counts up.
- **Request log** streams lines as they're sent, e.g. `[    0.214] 200 GET /api/users/1 bob · cross-account read: bob → alice's object`.
- The green bar's right side reads `running N/500`.

Controls during a run:

| Step | Expected |
| --- | --- |
| Press <kbd>p</kbd> (or **Pause**) | The status becomes `paused` and the log stops |
| Press <kbd>p</kbd> again | Resumes |
| Click a severity chip (e.g. **high 7**) above the list | Only those findings are listed; <kbd>j</kbd>/<kbd>k</kbd> move within them. **all** clears it. Under the header, **start with:** links the most severe finding |
| Press <kbd>j</kbd> / <kbd>k</kbd> | Moves through findings. The right pane shows the finding as a man page (NAME, SYNOPSIS, DESCRIPTION, IMPACT, FIX, EVIDENCE) |
| In the log, search for `/api/admin` | Only `Skipped (…): /api/admin/users is excluded` notes. No request was sent |
| In the log, look for `POST` | None sent. Only notes that the validation, identity and business-logic checks were skipped. **No POST/PUT/PATCH/DELETE was sent** |

**Expected findings (vulnerable demo, read-only, admin excluded):** 23. Without the exclusion there are 24: "Admin function accessible…" appears too. By severity: 2 critical, 7 high, 4 medium, 9 low, 2 info.

| Severity | Finding | Endpoint |
| --- | --- | --- |
| crit | JWT is signed with a guessable secret | credential: alice |
| crit | JWT with alg "none" is accepted | GET /api/me |
| high | CORS reflects any origin and allows credentials | GET /api/me |
| high | Environment file publicly accessible | GET /.env |
| high | Endpoint accessible without authentication | GET /api/invoices/{id} |
| high | Cross-account data access (BOLA/IDOR) | GET /api/users/{id} |
| high | Cross-account data access (BOLA/IDOR) | GET /api/invoices/{id} |
| high | Admin function accessible to a non-admin account *(only without the exclusion)* | GET /api/admin/users |
| high | Possible SQL injection (database error on quote) | GET /api/search · q |
| med | CORS allows the "null" origin | GET /api/me |
| med | Stack trace exposed in response | GET /api/search |
| med | Input reflected into HTML without encoding (XSS risk) | GET /api/greet · name |
| med | No rate limiting observed | GET /api/me |
| low | Server technology and version disclosed; `X-Content-Type-Options` missing; authenticated responses may be cached | GET /api/me (3 findings) |
| low | **Data-quality indicators** read from `GET /api/profile-data`: malformed email, implausible age (212), negative quantity, `updatedAt` earlier than `createdAt`, implausible birth date, unverified account holding a privileged role | GET /api/profile-data (6 findings, confidence **low**: "needs human review") |
| info | API specification is publicly accessible | GET /openapi.json |
| info | Sequential numeric identifiers ("id") | parameter: id |

`GET /api/users/{id}/orders` checks ownership properly, so it must **not** appear. That is the false-positive check.

## 9. Stop, budget and stop conditions

| Step | Expected |
| --- | --- |
| **3:controls**: rate `1`, save. Start a scan, then press <kbd>x</kbd> and confirm | Status `stopped`, with "Ended early. Stopped by user." Findings so far are kept |
| **3:controls**: budget `10`, rate `20`, save. Start a scan | Status `halted` with "Request budget of 10 reached." and exactly `10/10 requests` |
| Budget `500`, rate `2`. Start a scan, then stop the demo (Ctrl-C in terminal 1) | After 10 failed requests: `halted`, "Stop condition: 10 consecutive server errors or timeouts." Restart the demo afterwards |
| Start a scan, then restart breakAPI (Ctrl-C, `npm start`) | The scan shows `interrupted`: "The breakAPI server restarted during the scan." |
| Set **Max duration** to `1` minute and rate `0.5`, start a scan | After about a minute: `halted`, "Maximum scan duration of 1 minutes reached." |

Reset the controls to rate `20`, budget `500` and duration `30` before continuing.

## 10. Report

Remove the `/api/admin/*` exclusion, run a full scan, then on the finished scan:

| Step | Expected |
| --- | --- |
| Press <kbd>o</kbd> (or **Report**) | A man-page-style report opens in a new tab, with NAME, SUMMARY, FINDINGS, AUTHORIZATION, **UNDERTAKING**, **VERIFICATION**, CONTROLS, **AUTH LIMITATIONS** and LIMITATIONS |
| Read **UNDERTAKING** | Who typed what, when, the version and a hash; the clauses; the "not legal advice" notice |
| Read **VERIFICATION** | For localhost: "Local development only — no ownership proof was made." |
| Click **Evidence** on a finding | The request and response, with `authorization: Bear••••xx` masked |
| Print the report (Cmd/Ctrl-P) | Switches to a light layout; evidence is expanded |
| **JSON** (next to Report) | A `breakapi-scan_….json` file with `authorization`, `controls`, `scan.findings` and `limitations` |
| Sign out, then open the report URL | Redirects to sign-in. Reports are never public |

## 11. Fix and retest

1. Restart the demo in fixed mode: `DEMO_FIXED=1 npm run demo`.
2. On the finished read-only scan, press <kbd>r</kbd> (**Retest**).
3. When it completes, a **Retest** panel shows **13 fixed · 11 still open · 0 new** (for a scan without the admin exclusion). The fixed list:
   - JWT with alg "none" is accepted
   - CORS reflects any origin and allows credentials, and CORS allows the "null" origin
   - Endpoint accessible without authentication (invoices)
   - Cross-account data access (users and invoices)
   - Admin function accessible to a non-admin account
   - The six data-quality indicators from `/api/profile-data`

   Still open: the guessable JWT secret, `/.env`, SQL injection, stack trace, XSS, no rate limiting, three header findings and the two info items.
4. Rate limiting: restart with `DEMO_FIXED=1 DEMO_RATE_LIMIT=5 npm run demo`, set **Request rate** to `2` (so normal checks stay under the limit), and retest. "No rate limiting observed" moves to **fixed**, and the log shows `Rate limiting observed on GET /api/me … (HTTP 429)`.
5. The report of a retest includes a RETEST section with the same comparison.

## 12. Synthetic writes: validation, identity and business logic

These checks send mutated requests with **synthetic data**, so they need three separate decisions, all of which you make:

1. **Authorization tab:** record a new authorization with **Also allow write requests** ticked (re-add undertaking; use host `localhost:4010`).
2. **Target tab:** tick **Fake-data writes** on `POST /api/login`, `POST /api/users` and `POST /api/orders` only. `PATCH /api/users/{id}` stays unticked.
3. **Test accounts:** alice must own `email=alice@demo.test` (§6).

(`node testdata/seed.mjs --writes --scan` does all three for the demo.)

Run the vulnerable demo plainly, then a scan.

**Gates to confirm first**

| Step | Expected |
| --- | --- |
| Before ticking anything, run a scan with write requests authorized | Zero POST/PATCH requests in the log; notes say each synthetic check was skipped because nothing is opted in. The cross-account `PATCH /api/users/{id}` test logs `… is not opted in to synthetic writes` too |
| Tick the opt-ins but **un**tick "allow write requests" on the authorization (the checkboxes become disabled) | Still nothing is sent: both the global switch and the per-endpoint opt-in are required |
| Re-import `demo/openapi.json` | The ticks stay as you set them; an import never turns one on |

**Expected with everything on (vulnerable demo, no exclusions): 43 findings** (2 critical, 12 high, 8 medium, 19 low, 2 info), about 34 writes of the default 50. New compared with §8:

| Severity | Finding | What it shows |
| --- | --- | --- |
| high | Privileged fields can be set by the client (mass assignment) | `POST /api/users` honoured `role: admin` |
| high | New account has full access before its email is verified | the signup token worked on `/api/me` while `email_verified` was false |
| high | Negative "quantity" accepted; The client decides the "price" | `POST /api/orders` took `quantity -1` and `price 0.01` |
| med | Malformed email address accepted | `not-an-email` was stored |
| med | Email addresses are not normalized | a case-variant of the same address created a second account |
| med | A trivially weak password is accepted | `123456` was accepted |
| med | Login responses reveal whether an account exists | known user: 401 "wrong password"; unknown: 404 "no such user" |
| med | Negative "price" accepted | |
| low | Text accepted for numeric field "age"/"quantity"/"price"; Implausible value accepted for "age"; Unbounded "quantity" accepted; Identical requests create duplicate records; Cookie "sid" is missing HttpOnly, SameSite; plus data-quality indicators in the created records | |
| high | No rate limiting observed on `POST /api/login` | a bounded burst of at most 10 login attempts using a **synthetic** identity, never alice's |

Details to check in the evidence:
- Request bodies are shown. Emails end in `@example.invalid` (a reserved, undeliverable domain) and names carry a `breakapi-<scan id>` marker.
- Nothing was sent to alice's or bob's real objects: synthetic writes target collections or the account's own object only.
- `DELETE` never appears in the log.

**Fixed demo.** With `DEMO_FIXED=1`, scan with the same settings: **11 findings** remain (the unchanged read-side weaknesses and the login rate-limit finding), and none from validation, identity or logic. An API that validates and recomputes server-side (for example one that ignores a client-sent price) gets no false positive: a value only counts as accepted when the response echoes it back or its absence can't be told, and "can't be told" findings are marked confidence **low**.

## 13. Write budget and limits

| Step | Expected |
| --- | --- |
| Set **Write budget** to `3` and rerun the §12 scan | The log shows `Skipped (…): write budget of 3 reached`; `Writes sent` in the report is at most 3; read-only checks still complete |
| Set **Write budget** to `0` | No write is sent at all, even with everything opted in |
| Try **Write budget** `9999` and **Max duration** `9999` | Clamped to 500 writes and 120 minutes |

## 14. Expiry, revocation and credential retention

| Step | Expected |
| --- | --- |
| Record an authorization that expires 2 minutes from now; wait about 3 minutes and reload | Authorization **expired**; the accounts table shows **deleted** for every credential; audit shows `credentials.purged … authorization expired`; **Start scan** is blocked |
| Record a fresh authorization, re-add alice and bob, start a slow scan (rate `1`), then **Revoke authorization** | The running scan stops (`stopped`, "Authorization was revoked."); credentials are deleted; pre-flight shows `[ FAIL ] Authorization was revoked…` |
| **2:accounts** → **Delete all credentials** | Every credential shows **deleted** |
| In the project list, click **Delete** on the row (or **5:settings → Delete this project**; owners only) | A confirmation dialog, then the project and all its scans and reports are gone |
| An authorization recorded before this version (no undertaking) | Pre-flight: "The testing undertaking has not been accepted… Record the authorization again". Nothing is deleted |

## 14b. Project settings, members and privacy

| Step | Expected |
| --- | --- |
| As Dana, open a project → **5:settings** (or press <kbd>5</kbd>) | Dana is listed as **owner** under Members |
| Add `nobody@example.com` | "No active breakAPI user has that email. Ask an administrator to issue them an account first." |
| Add `uma@example.com` | Uma is a **member**. Signed in as Uma, the project now appears in her list; she can configure it and run scans |
| As Uma, look at the project list and the settings tab | The list row says **Leave**, not Delete, and the settings tab has no delete section (owners only). The API returns 403 |
| As Uma, click **Leave** (list row or settings) | It disappears from her list; its URL now returns "Project not found", as does any of its scan or report URLs |

## 15. Scope enforcement

| Step | Expected |
| --- | --- |
| Authorization hosts `localhost:9999` only, base URL `http://localhost:4010` | Pre-flight: `[ FAIL ] Base URL host "localhost:4010" is not in the authorized scope.` and **Start scan** is disabled |
| `curl -X POST -b "bp_sid=<your session cookie>" -H "x-breakapi: 1" http://127.0.0.1:7300/api/projects/<id>/scans` | `422 Scan blocked: …` The server enforces this, not only the UI |
| Authorization host `api.example.com`, base URL `https://api.example.com` | `[ FAIL ] Control of "api.example.com" is not verified…` |

## 16. Hosted (production) mode

```bash
BREAKAPI_ENV=production npm start
```

| Step | Expected |
| --- | --- |
| Start with no other settings | It refuses to start and lists the three missing settings (public URL, secret key, SMTP) |
| Start with `BREAKAPI_PUBLIC_URL=https://breakapi.example.com BREAKAPI_SECRET_KEY=$(node src/cli.js gen-key) SMTP_HOST=smtp.example.com HOST=127.0.0.1` | Starts; the settings line shows local and private targets **refused** and the key "from environment". `curl -sI localhost:7300/` shows `strict-transport-security` |
| In that mode, record an authorization for `localhost:4010` or `10.0.0.5` | Pre-flight: `"localhost:4010" cannot be tested from this server: … local targets are disabled here` (and the private-network equivalent) |
| `curl localhost:7300/healthz` | `{"ok":true,"version":"0.2.0"}` |
| Ctrl-C (SIGTERM) | "stopping scans and closing", then exits |

Admin recovery without email (server stopped): `node src/cli.js create-admin --email you@example.com`, `node src/cli.js reset-password --email …`, `node src/cli.js list-users`.

## 17. Automated checks

```bash
npm test
```

Runs 28 tests across two suites:

- [test/e2e.test.js](test/e2e.test.js) (15): authorization validation, the undertaking, per-host verification and re-verification, cloud-metadata blocking, scope blocks, a full read-only scan (no writes or DELETE, raw tokens never stored), budget, stop and retest, revocation and credential purge, report escaping, the write gate, the synthetic findings, a patched API producing none, and the write budget and duration limits.
- [test/auth.test.js](test/auth.test.js): first-run setup, generic sign-in failures and session rotation, sign-in rate limiting, issued accounts and admin-only routes, project privacy and membership, authorizer confirmation by email (confirm, resend, decline), forgot/reset and password change, disabling users and last-admin protection, CSRF origin checks and prototype pollution, open sign-up with email verification, production config and SSRF guards (including DNS that resolves to loopback), the password policy and health endpoints, and SMTP delivery against a fake server (including header-injection and dot-stuffing).
- [test/access.test.js](test/access.test.js): setup tokens at sign-in, the 30-day limit, one session at a time, access ending on restart, issuing again, the disclaimer.
- [test/lab.test.js](test/lab.test.js): every demo lab example finds what it promises, the lab can't be aimed elsewhere, its exception doesn't reach real projects, and its limits.

## For larger, multi-endpoint scenarios

[TEST-SCENARIOS.md](TEST-SCENARIOS.md) is a second, deeper guide: 40 scenarios built around `demo-manual.txt` and a 33-endpoint wide list, with measured expected results, plus an end-to-end campaign that strings them together.

## Troubleshooting

- **Authenticated checks find nothing:** demo tokens expire after 24 hours. Regenerate them with `node testdata/tokens.mjs` and re-add the accounts.
- **"A scan is already running":** each project runs one scan at a time. Stop it, or wait for it to finish.
- **Synthetic checks "skipped":** check all three decisions in §12 (write requests authorized, endpoints ticked, regular test account present). The scan log says which one is missing.
- **Start a clean slate:** stop breakAPI and delete `data/`. This removes every project, the encryption key and the access token.
