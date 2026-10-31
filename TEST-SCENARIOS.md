# breakAPI test scenarios: one demo target, many endpoints

[TESTING.md](TESTING.md) walks through every *feature* once. This guide is different: it stresses breakAPI with **one local API (`localhost:4010`) and lists of 8 to 33 endpoints**, changing one thing at a time and predicting what should change in the results. It needs no code changes, only the app, the demo, and the files in `testdata/`.

It has 39 scenarios in six groups, then one end-to-end campaign that strings them together.

| Group | What it tests | Scenarios | Time |
| --- | --- | --- | --- |
| **A** Import | Manual, wide, OpenAPI merge, bad input | A1–A5 | ~15 min |
| **B** Coverage | The 8-endpoint list under 12 different setups | B1–B12 | ~60 min |
| **C** Wide list and limits | 33 endpoints, budgets, pause/stop, fake-data writes | C1–C6 | ~35 min |
| **D** Scope and consent | Ports, base URLs, windows, authorizer confirmation | D1–D8 | ~35 min |
| **E** Projects and people | Deleting projects, members, privacy, unowned projects | E1–E7 | ~25 min |
| **F** Campaign | Everything, in order, with a sign-off table | F1 | ~90 min |

Every number below was **measured** on this build against the bundled demo, by running these exact setups. If yours differ, that is the bug report.

---

## 0. Before you start

### Ports and files

| Thing | Value |
| --- | --- |
| Demo API (the target) | `http://localhost:4010` |
| breakAPI | `http://localhost:7300` |
| The 8-endpoint list | [`testdata/demo-manual.txt`](testdata/demo-manual.txt) |
| The 33-endpoint list | [`testdata/demo-manual-wide.txt`](testdata/demo-manual-wide.txt) |
| OpenAPI spec of the demo (14 operations) | [`demo/openapi.json`](demo/openapi.json) |
| Fresh test tokens | `node testdata/tokens.mjs` |

**Always use `localhost:4010`** for the authorization host and the base URL (they must agree). Don't use `0.0.0.0`: it isn't treated as local, so you would be asked to prove ownership of it.

### What is in the wide list

`demo-manual-wide.txt` has 33 endpoints. The first 8 are exactly `demo-manual.txt`. Of the rest, the demo really serves only `/api/profile-data`, `/openapi.json` and `/api/health`. The other 22 (teams, orders, billing, export, `/api/keys`, `/api/internal/*`, …) return **404 on purpose**: they are realistic noise, so you can check that a long list of endpoints that don't exist adds requests but not findings.

### Reset (do this before each group, and any time a scenario says "fresh demo")

The demo keeps everything fake-data scans create, and test tokens last 24 hours.

```bash
# stop breakAPI and the demo (Ctrl-C), then:
rm -rf data                  # forgets all users and projects. Skip it to keep your accounts
npm run demo                 # terminal 1. Note the three tokens it prints
npm start                    # terminal 2. First run prints a one-time setup token
```

### People

| Who | How | Used for |
| --- | --- | --- |
| **Dana Ruiz** `dana@example.com` | First administrator (`/#/setup`, setup token from terminal 2) | Runs nearly everything |
| **Uma** `uma@example.com` | Dana → Admin → Invite a user; open the link from `data/outbox/*.eml` | Member, privacy checks |
| **Olu Owner** `olu@example.com` | **No account.** Only receives an emailed link | Authorizer confirmation |

### The standard project (every scenario starts from this, then changes one thing)

Create a project called `SC-<scenario id>` (for example `SC-B1`), then:

| Tab | Set |
| --- | --- |
| **0:authorization** | Authorizer Dana (your own name and email, so the undertaking is yours). Hosts `localhost:4010`. Expires in 7 days. **All nine** tests ticked. **Allow write requests unticked.** Tick the undertaking, type `Dana Ruiz`, **Record authorization** |
| **1:target** | Base URL `http://localhost:4010`. Import `testdata/demo-manual.txt` as **Manual list** → "Imported 8 endpoints" |
| **2:accounts** | Add **alice**: Regular user, Bearer, alice's token, IDs `id=1` and `email=alice@demo.test` (two lines). Add **bob**: Bearer, bob's token, IDs `id=2` and `email=bob@demo.test` |
| **3:controls** | The **fast controls**: Request budget `1000`, Speed `50`, Burst size `20`, Burst speed `100`, Timeout `5000`, Stop after `10`. Leave the rest at defaults |

Then **4:scans → Start scan** (or press <kbd>s</kbd>). At speed 50 a scan of the 8-endpoint list takes a few seconds.

**Reading results:** the scan header shows `N/1000 requests`, the severity tally, and one count per check. The log at the bottom lists every request and every skip note. Press <kbd>j</kbd>/<kbd>k</kbd> through findings.

Because all nine tests are ticked but write requests are off, **every scan logs three "skipped" notes** (validation, identity and business-logic checks have nothing opted in). That is expected and doesn't change findings.

---

## A. Importing endpoints

### A1. Import the 8-endpoint list
**Steps:** standard project, step 1:target.
**Expect:** "Imported 8 endpoints". The table says `8 of 8 tested`. `/api/health` has **Needs login** unticked; `/api/admin/users` has **Admin only** ticked (breakAPI infers it from the path as well as from the `admin` flag); `/api/search?q` and `/api/greet?name` show their query names; `{id}` paths show as written.
**Why:** this is the list every B scenario depends on.

### A2. Bad lines are rejected with a line number
**Steps:** a scratch project. On 1:target, paste each into **Content** (format *Manual list*), tick **Replace**, **Import**.

| Paste | Expect |
| --- | --- |
| `FETCH /api/x` | `Line 1: expected "METHOD /path [public] [admin]"` |
| `GET api/users` (no leading slash) | the same message |
| `GET` | the same message |
| `# only comments` | `No endpoints found.` |
| `GET /api/a`, then `POST /ok`, then `BROKEN line here` (three lines) | `Line 3: expected …`, and **nothing** from lines 1–2 is imported |
| `GET /api/x?q=1  # trailing comment`, then `GET /api/y` | accepted: "Imported 2 endpoints" (comments after `#` are ignored) |

### A3. Import the 33-endpoint wide list
**Steps:** new project `SC-A3`, import `testdata/demo-manual-wide.txt` as Manual.
**Expect:** "Imported 33 endpoints" (comment and blank lines are ignored). The table says `33 of 33 tested`. Lines ending `public` have Needs login off; lines ending `admin` have Admin only on (`/api/keys`, `/api/audit`, `/api/internal/metrics`, `/api/internal/flags`).

### A4. Merge the OpenAPI spec on top of the manual list
**Steps:**
1. Project with `demo-manual.txt` imported. Untick **Needs login** on the `GET /api/invoices/{id}` row.
2. Open **Import more endpoints**, choose **OpenAPI 3 / Swagger 2 (JSON)**, load `demo/openapi.json`, leave **Replace** unticked, **Import**.

**Expect:** 14 endpoints in total (the 8 overlap; the spec adds `PATCH`, `DELETE /api/users/{id}`, `POST /api/login`, `POST /api/users`, `POST /api/orders` and `GET /api/profile-data`). The invoice row **keeps Needs login unticked**: existing rows win on overlap.
3. Import the spec again with **Replace** ticked.

**Expect:** still 14, and the invoice row now **Needs login ticked** (the spec's own setting). `DELETE /api/users/{id}` shows **never** in the Test column in both cases. Every POST/PATCH row's **Fake-data writes** box is unticked: imports never turn it on.

### A5. Importing the same list twice does not duplicate
**Steps:** import `demo-manual.txt` twice without Replace.
**Expect:** still 8 endpoints.

---

## B. The 8-endpoint list under 12 setups

Start each from the standard project. Compare to **B1**.

### B1. Baseline: alice and bob
**Expect:** completes in about 90 requests with **18 findings: 2 critical, 7 high, 4 medium, 3 low, 2 info**, and 0 writes.

| Sev | Finding | Where |
| --- | --- | --- |
| crit | JWT is signed with a guessable secret | credential: alice |
| crit | JWT with alg "none" is accepted | GET /api/me |
| high | CORS reflects any origin and allows credentials | GET /api/me |
| high | Environment file publicly accessible | GET /.env |
| high | Endpoint accessible without authentication | GET /api/invoices/{id} |
| high | Cross-account data access (BOLA/IDOR) | GET /api/users/{id} |
| high | Cross-account data access (BOLA/IDOR) | GET /api/invoices/{id} |
| high | Admin function accessible to a non-admin account | GET /api/admin/users |
| high | Possible SQL injection (database error on quote) | GET /api/search · q |
| med | CORS allows the "null" origin | GET /api/me |
| med | Stack trace exposed in response | GET /api/search |
| med | Input reflected into HTML without encoding (XSS risk) | GET /api/greet · name |
| med | No rate limiting observed | GET /api/me |
| low | Server technology and version disclosed; nosniff missing; authenticated responses may be cached | GET /api/me (three) |
| info | API specification is publicly accessible | GET /openapi.json |
| info | Sequential numeric identifiers ("id") | parameter: id |

**Must not appear:** anything for `GET /api/users/{id}/orders` (its ownership check works). That is the false-positive control for the whole guide.

### B2. Add an admin account
**Steps:** add **root**: role **Admin**, root's token, IDs `id=3`. Rescan.
**Expect:** about 93 requests (three more), the **identical 18 findings**. An admin account is never used as the attacker, so it adds no false positives.

### B3. Only one account
**Steps:** remove bob. Rescan.
**Expect:** about 80 requests, **16 findings**. The two cross-account findings (`/api/users/{id}` and `/api/invoices/{id}`) are gone, and the log says: *Cross-account (IDOR/BOLA) checks need at least two test accounts with resource IDs — skipped.* Nothing else changes: **absence is not safety**, and the log tells you why.

### B4. No accounts at all
**Steps:** remove alice and bob. Rescan.
**Expect:** about 63 requests, **8 findings** (0 crit, 3 high, 2 med, 2 low, 1 info): CORS-with-credentials, `/.env`, invoices without authentication, CORS null, no rate limiting, tech disclosure, nosniff (all reported against `GET /api/health`, the only endpoint reachable anonymously) and the public spec. Notes: *No test account credentials available — authenticated checks will be limited* and the cross-account skip. No SQL injection or XSS finding: those endpoints need a login.

### B5. The first account's credential is broken
**Steps:** the account **order** matters here, and a removed account that you add back goes to the *end* of the list. So: remove **both** accounts, then add **alice first** with credential `not-a-real-token` (IDs `id=1` and `email=alice@demo.test`), then **bob second** with his real token. Rescan.
**Expect:** about 84 requests, **13 findings**. Compared with B1 you lose **five**: the `/api/users/{id}` BOLA, SQL injection, the stack trace, XSS, and "authenticated responses may be cached". "JWT guessable" now names **bob**. The log shows `owner baseline for alice returned 401; cross-account test skipped`.
**Why it matters:** the **first account in the list is the primary one**: input and header checks run as it. A bad first credential quietly removes coverage, and only the baseline notes hint at it. See Known issue **KI-2**. Fix by removing both and adding them back with a valid account first. (If you only remove and re-add alice, bob becomes primary and the scan loses almost nothing: 17 findings, only the missing token itself.)

### B6. Mislabel an endpoint as public
**Steps:** untick **Needs login** on `GET /api/invoices/{id}`. Rescan.
**Expect:** about 88 requests, **17 findings**: only "Endpoint accessible without authentication @ invoices" disappears. The cross-account invoices finding stays, because the check still compares what alice and bob each receive.
**Why:** "Needs login" is *your statement of what should happen*. breakAPI reports differences from it, so a wrong label hides that one finding. Label carefully.

### B7. Mislabel `/api/me` as public
**Steps:** untick **Needs login** on `GET /api/me`. Rescan.
**Expect:** about 87 requests, still **18 findings**, but **seven findings move** from `GET /api/me` to `GET /api/users/{id}`: JWT alg none, CORS with credentials, CORS null, no rate limiting, tech disclosure, nosniff, cacheable. Checks that need "an authenticated endpoint" pick the first one that requires login.
**Why:** labels change *which endpoint is used as evidence*, not whether the weakness is found.

### B8. The admin flag
**Steps:** (a) Rescan after **unticking Admin only** on `/api/admin/users`.
**Expect (a):** about 89 requests, **17 findings**: "Admin function accessible to a non-admin account" is gone. (b) Re-tick it. Then re-import a list where that line is `GET /api/admin/users` *without* the word `admin`, with Replace.
**Expect (b):** still **18 findings** and the admin finding is back: a path containing `/admin/` is treated as admin-only automatically.

### B9. Exclusions
**Steps:** 3:controls → Exclusions, two lines: `/api/admin/*` and `/api/search*`. Save, rescan.
**Expect:** about 80 requests, **15 findings**. Gone: admin function, SQL injection, stack trace. The log has seven `Skipped (…): … is excluded` notes. **No request in the log** touches those paths.

### B10. Untick endpoints
**Steps:** clear the exclusions. Untick **Test** on `/api/search` and `/api/greet`. Rescan.
**Expect:** about 78 requests, **15 findings**. Gone: SQL injection, stack trace, XSS.

### B11. Fix the API, then retest
**Steps:** run B1 to completion. Stop the demo; restart it as `DEMO_FIXED=1 npm run demo` (same port; the tokens you already added stay valid for 24 hours, so there is nothing to re-enter). Open the finished B1 scan → **Retest** (<kbd>r</kbd>).
**Expect:** about 94 requests, **11 findings** (1 crit, 2 high, 3 med, 3 low, 2 info). A **Retest** panel: **7 fixed, 11 still open, 0 new**.
- *Fixed:* JWT alg none, CORS with credentials, CORS null, invoices without authentication, both BOLA/IDOR findings, admin function.
- *Still open:* guessable JWT secret, `/.env`, SQL injection, stack trace, XSS, no rate limiting, the three header findings, the public spec, sequential IDs.

### B12. A rate-limited API
**Steps:** restart the demo as `DEMO_RATE_LIMIT=5 npm run demo` (existing tokens still work). Set **Speed** to `2` (so ordinary checks stay under 5 per second). Rescan.
**Expect:** about 76 requests (and about 40 seconds), **17 findings**. "No rate limiting observed" is gone, and the log shows *Rate limiting observed on GET /api/me after 6 requests (HTTP 429)*.

---

## C. The wide list, limits and fake-data writes

### C1. Wide list baseline
**Steps:** standard project, but import `demo-manual-wide.txt` instead (alice and bob as usual). Scan.
**Expect:** about 210 requests, **24 findings (2 crit, 8 high, 3 med, 9 low, 2 info)**. Against B1:
- **Six new lows** from `GET /api/profile-data`, which the wide list adds: malformed email in data, implausible age (212), negative quantity, `updatedAt` before `createdAt`, implausible birth date, unverified account holding a privileged role. They are read from responses and marked low confidence.
- "No rate limiting observed @ GET /api/me" is gone (see below).
- **One new high that is not real:** *No rate limiting observed @ GET /api/v2/users/{id}/sessions*. See Known issue **KI-1**.
- **About 140 of the 210 responses are 404** (139 when measured), and the log has about 16 notes like *owner baseline for alice returned 404; cross-account test skipped* (19 counting the three fake-data skips). None of the 22 not-found endpoints produces a finding of its own: that is the actual test.

### C2. Budget halts a long scan, then a retest completes it
**Steps:** C1 setup, but Request budget `60`. Scan.
**Expect:** `halted`, **exactly 60/60 requests**, reason *Request budget of 60 reached.* Findings so far are kept (about 14). In the header only the first two checks (config, exposure) completed; the rest show incomplete.
**Steps (cont.):** raise the budget to `1000`, open the halted scan, **Retest**.
**Expect:** `completed`, about 210 requests, 24 findings. The retest panel says **0 fixed, 14 still open, 10 new, 0 not re-checked**.

### C3. Pause, resume, stop
**Steps:** C1 setup with Speed `2` (this takes about two minutes). Start.
1. After ~10 seconds press <kbd>p</kbd>. 2. Watch the counter for 10 seconds. 3. Press <kbd>p</kbd> again. 4. After another ~10 seconds press <kbd>x</kbd>, confirm in the dialog.

**Expect:** status goes `running` → `paused` (the request counter and log freeze) → `running` → `stopped` with reason *Stopped by dana@example.com.* Findings so far remain; **Report** and **Retest** become available.

### C4. Maximum duration
**Steps:** C1 setup, Speed `0.5`, Max duration `1` minute. Start.
**Expect:** after about a minute: `halted`, *Maximum scan duration of 1 minutes reached*, roughly 30 requests.

### C5. Fake-data writes on the merged list
**Steps:**
1. Fresh demo. Standard project, then merge the OpenAPI spec (A4 step 2, Replace unticked): 14 endpoints.
2. 0:authorization → **Replace authorization**, same values, but tick **Allow write requests**, tick the undertaking, type your name.
3. 1:target → in **Fake-data writes** tick `POST /api/login`, `POST /api/users`, `POST /api/orders`. Leave `PATCH /api/users/{id}` unticked.
4. Add the email IDs to both accounts (`email=alice@demo.test`, `email=bob@demo.test`) if you haven't.
5. Scan.

**Expect:** about 108 requests of which **34 are writes**, **43 findings: 2 crit, 12 high, 8 med, 19 low, 2 info**. It matches TESTING.md §12. In the log the only POSTs are to the three ticked endpoints, bodies show `@example.invalid` addresses and a `breakapi-…` marker, and **no DELETE** is ever sent. The cross-account `PATCH` shows `Skipped … is not opted in to synthetic writes`.

### C6. Opt in PATCH, and meet the leftovers
**Steps:** do **not** restart the demo. Tick **Fake-data writes** on `PATCH /api/users/{id}`. Open the C5 scan → **Retest**.
**Expect:** about 115 requests and **41 writes**, **45 findings**. The PATCH calls appear in the log: `bob → alice's object` and `alice → bob's object` both get **403**, so there is **no** cross-account write finding (the API protects writes properly). The retest panel shows **0 fixed, 2 new**: *Malformed email address in data* and *Implausible age in data (-1)*, both on `GET /api/admin/users`.
**Why:** those two are real, and they are **leftovers of your own test**: C5's sign-ups stored a malformed email and an age of -1, and the admin list now returns them. Fake-data scans leave records behind. Restart the demo to clear them (see KI-4).

---

## D. Scope, ports and consent

### D1. The port is part of the scope
**Steps:** standard project, but record the authorization with host `localhost:4011`, keep base URL `http://localhost:4010`.
**Expect:** 4:scans pre-flight: `[ FAIL ] Base URL host "localhost:4010" is not in the authorized scope.` **Start scan** is disabled. Pressing <kbd>s</kbd> does nothing.
**Fix:** replace the authorization with `localhost:4010`.

### D2. A host with no port covers every port
**Steps:** record the authorization with host `localhost` (no port). Base URL stays `http://localhost:4010`.
**Expect:** the scan **runs** (about 90 requests, 18 findings, same as B1).
**Why it matters:** a bare host name authorizes *every port on that host*. List the port (`localhost:4010`) whenever you mean one service. See Known issue **KI-3**.

### D3. A base URL prefix doubles the paths
**Steps:** standard project but base URL `http://localhost:4010/api`. The list's paths already start with `/api`.
**Expect:** the scan runs but about **9 findings** (1 crit, 2 high, 2 med, 2 low, 2 info): requests go to `/api/api/users/1` and so on, so almost everything is a 404. Open the log to see the doubled paths.
**Fix:** base URL `http://localhost:4010`.

### D4. The test window
**Steps:** standard project. 3:controls → **Window opens** tomorrow, save.
**Expect:** pre-flight `[ FAIL ] Test window has not started (opens …)`. Under the date picker a line echoes the date in the app's own format (`= 31 Oct 2026, …`), so you can tell the picker's locale from the real date.
**Then:** set **Window closes** one minute from now and **Window opens** empty; start a slow scan (Speed `0.5`).
**Expect:** the scan halts with *Test window closed.* a minute in.

### D5. A different authorizer (Olu) confirms by email
**Steps:** standard project, but on 0:authorization set **Authorizer's name** `Olu Owner` and **email** `olu@example.com`.
1. The undertaking step turns into **Send it to the authorizer**. Tick the recorder's confirmation, **Record and email the authorizer**.
2. The authorization says **awaiting confirmation**; pre-flight says *Waiting for olu@example.com to confirm*; Start scan is disabled.
3. Open the newest `data/outbox/*.eml`, copy the `/#/confirm/…` link into a **private window** (no sign-in).
4. Check the page shows the hosts, tests, write setting, expiry, "What this does not prove" and the clauses. Tick the box, type `Dana Ruiz` (the wrong name) → *Type your full name (Olu Owner)…*. Type `Olu Owner` → **Confirm authorization**.

**Expect:** Dana's page shows **active**, *Confirmed … link emailed to olu@example.com*; a scan starts. Its report header says **Started by Dana Ruiz** and lists who recorded and who confirmed. Opening the link again says it is invalid or already used.

### D6. The authorizer declines, and a resend replaces links
**Steps:** record another delegated authorization to Olu. Click **Resend the email**, then try the **first** link: invalid. Open the newest link and **Decline** (confirm in the dialog).
**Expect:** the authorization shows **declined**; scans stay blocked.

### D7. The undertaking needs the right name
**Steps:** record as yourself but type `Someone Else`.
**Expect:** an inline error above the button *and* a toast: *Type the authorizer's full name exactly as entered above…*. Nothing is recorded.

### D8. Revoke mid-scan
**Steps:** standard project, Speed `2`, wide list. Start, then **Revoke** after ~10 seconds (confirm in the dialog).
**Expect:** the scan stops (`stopped`, *Authorization was revoked.*), the **2:accounts** table shows every credential as **deleted**, and pre-flight lists the revocation.

---

## E. Projects and people (including deleting a project)

Dana is the admin; Uma is invited and verified (see Section 0).

### E1. Delete a project from the project list
**Steps:** create `SC-E1`. Go to the project list (click `breakAPI` top left, or press <kbd>u</kbd>). On its row click the red **Delete** button.
**Expect:** a dialog: *Delete "SC-E1"? This permanently removes its authorization record, credentials, scans and reports.* **Delete project** → toast "Project deleted", the row is gone.

### E2. Delete from the project's settings, and the old link
**Steps:** create `SC-E2`, open it, press <kbd>5</kbd> (or click `5:settings`). Scroll to **Delete this project** and delete it. Then open `#/p/<its id>/team` for a project that still exists.
**Expect:** the project is gone and you land on the list. The old `…/team` address opens the settings tab (the tab was renamed).

### E3. Delete a project while it is scanning
**Steps:** standard project on the wide list at Speed `2`. Start a scan, wait 10 seconds, delete the project from the list.
**Expect:** the scan stops, the project and its scan disappear, and opening the scan's report URL gives not found.

### E4. A member can leave but not delete; non-members see nothing
**Steps:** as Dana create `SC-E4`; **5:settings** → add `uma@example.com`.
1. As Uma (private window): the project appears in her list with **Leave**, not Delete. Its settings tab has no delete section.
2. As Uma open `…/p/<id>` for another of Dana's projects she isn't in: **Project not found** (not "forbidden").
3. Uma clicks **Leave** → confirm → the project disappears for her; the old URL says not found.

### E5. Admin sees counts, not other people's data
**Steps:** as Dana (admin) open **Admin**.
**Expect:** the server panel counts users, projects and running scans. Uma's projects are **not** in Dana's project list unless Dana is a member. The system audit log lists the invitation, sign-ins and role changes, each with the actor.

### E6. Claim a project nobody owns
Projects carried over from the single-operator version, or otherwise left without an owner, can't be opened by anyone. An admin can claim or delete them. Create one:
1. Stop breakAPI (Ctrl-C).
2. Add a project with no members to the data file:
```bash
node -e "const f='data/db.json',d=JSON.parse(require('fs').readFileSync(f));d.projects.prj_legacy={id:'prj_legacy',name:'Legacy project',createdAt:new Date().toISOString(),authorization:null,authorizationHistory:[],verifiedHosts:[],target:{baseUrl:'http://localhost:4010',endpoints:[]},accounts:[],controls:{},audit:[]};require('fs').writeFileSync(f,JSON.stringify(d))"
```
3. `npm start`, sign in as Dana. The project is **not** in her list. Open **Admin**.

**Expect:** a pane **Projects nobody owns** shows *Legacy project*, its address and a scan count. **Claim** → toast *You now own "Legacy project"*; it appears in the project list with **Delete**, and the pane disappears. Uma, signed in, cannot see the pane or the project.

### E7. Delete a project nobody owns
**Steps:** repeat E6 steps 1–3, running the command with `prj_legacy2` and `Legacy project 2` in place of the id and name, then click **Delete** in the pane and confirm.
**Expect:** it is removed with no claim step, and the system audit log shows `project.deleted`.

---

## F1. The campaign (all of it, in order)

Fresh `data/`, fresh demo. Fill in the right column as you go. A scenario passes when its **Expect** line from above holds.

| # | Do | Pass when | ✔ |
| --- | --- | --- | --- |
| 1 | Setup: create Dana; invite Uma (E setup) | Uma signs in, can't see Admin | |
| 2 | **A1**, then **A2** on a scratch project | 8 endpoints; every bad line rejected as listed | |
| 3 | Project `SC-B` from the standard recipe; **B1** | 18 findings; `/orders` not flagged | |
| 4 | **B3** (remove bob, scan); re-add bob and set **B9** exclusions (scan); clear them (scan) | 16, then 15, then 18 findings | |
| 5 | **B6** and **B8(a)**, scanning after each. Restore the labels afterwards, and rescan to confirm 18 | 17 each; right finding missing each time | |
| 6 | **D1** then fix; **D2**; **D3** then fix | blocked; 18; 9; back to 18 | |
| 7 | **D5** on a new project `SC-D` with Olu confirming; **D6** | scan blocked until Olu confirms; declined link kills it | |
| 8 | Add Uma as a member of `SC-D` (**E4** step 1). Uma starts a scan | Report says **Started by** Uma, **Recorded by** Dana, **Confirmed** via Olu's email | |
| 9 | **A3** + **C1** on `SC-C` (wide list) | 24 findings; ~140 404s; no finding on a 404 endpoint except KI-1 | |
| 10 | **C2** budget 60 → retest at 1000 | halted at exactly 60; retest 0/14/10 | |
| 11 | **C3** pause, resume, stop | statuses as listed | |
| 12 | Fresh demo. **C5** then **C6** | 43 then 45 findings; PATCH 403s | |
| 13 | On `SC-B` make sure the latest scan is a clean B1 run (rescan if not). Restart the demo as `DEMO_FIXED=1`; **Retest** | 7 fixed, 11 open, 0 new | |
| 14 | Download the **Report** of the retest; **Print** it | sections UNDERTAKING, VERIFICATION, AUTH LIMITATIONS; evidence printed | |
| 15 | **D8** revoke mid-scan on `SC-C` | stopped; credentials deleted | |
| 16 | **E1** and **E2** on two throwaway projects; **E3** with a running scan | all three deleted cleanly | |
| 17 | **E6**, **E7** | claimed project appears; deleted one doesn't | |
| 18 | Uma leaves `SC-D` (**E4**); Uma opens `SC-B` | Leave works; `SC-B` is "not found" for her | |
| 19 | Sign out; open a report URL | redirected to sign-in | |
| 20 | Dana: Sign out everywhere | every browser is signed out | |

**Sign-off:** tester ______ date ______ build ______ passed ___ / 20 steps. Attach the report from step 14 and the Admin audit log.

---

## Known issues seen while building these scenarios

These are real behaviors of the current build, observed by running the scenarios. They are recorded here, not fixed, because this guide was written without code changes.

| ID | What happens | Where | What you should do for now |
| --- | --- | --- | --- |
| **KI-1** | The rate-limit check prefers endpoints whose path looks sensitive (`login`, `session`, `token`, `password`, …) **even when that endpoint returns 404**, then reports "No rate limiting observed" at **high** severity. | **C1**: `GET /api/v2/users/{id}/sessions` (not served) | Treat a rate-limit finding on an endpoint whose own requests are all 404 as a false positive. Untick **Test** on endpoints that don't exist. |
| **KI-2** | The **first** test account is the primary one for input, header and baseline checks. If its credential is invalid, those checks quietly return nothing, with no "your first account failed" warning. | **B5** | Keep a known-good account first; after adding accounts, confirm the scan log has no `baseline … returned 401` lines. |
| **KI-3** | A scope host written **without a port** (`localhost`) covers **every** port on that host. | **D2** | Always write `host:port` in the authorization unless you mean every port. |
| **KI-4** | Fake-data scans leave records in the target; later scans can report them as data-quality findings. | **C6** | Restart or reset the target between synthetic scans; expect residue findings otherwise. |

If you want any of these fixed, say which. KI-1 and KI-2 change what scans report, so they would need new expected numbers in B5, C1 and the campaign.
