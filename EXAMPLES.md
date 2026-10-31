# breakAPI demo lab: every example

The demo lab lets anyone see breakAPI working, with no account and no setup. Each example runs a real scan against a practice API with flaws planted on purpose.

**Where:** open the app and choose **Try the demo lab**, or go to `/#/lab`.

**This is a testing demo application only.**

## Setup

There is nothing to set up. Every example does this for you:

1. Starts its own copy of the practice API ([demo/vulnerable-api.js](demo/vulnerable-api.js)) on a private port of the server. Nothing outside the server can reach it.
2. Creates a temporary project with an authorization, the API's endpoint list and any test accounts it needs.
3. Runs the scan, shows the results, and closes the practice API.

You choose an example and nothing else. There is no field for a URL, so the lab can't be pointed at a real system.

The practice API's data, accounts and secrets are all fake.

## How to run any example

1. Open **Demo lab**.
2. Optional: open **What it tests and how** on the example.
3. Press **Run**. Most runs finish within 5 seconds.
4. Read the results page:

| Part of the page | What it tells you |
| --- | --- |
| Severity counts | How many findings there are at each level, from critical to info |
| **target counted** | Requests, writes and DELETEs as counted by the practice API itself, not by the scanner |
| Phase buttons | Switch between scans, for examples with more than one |
| **Retest** | What was fixed, still open or new compared with the previous phase |
| **Findings** | Pick one to read what it means, its impact, the fix and the evidence |
| **Request log** | Every request the scan sent |
| **Report** | The printable report you would hand to a team |

**Limits:** two runs at a time on a server and 20 starts per visitor every 15 minutes. Runs are kept in memory for an hour, and are lost sooner if the app restarts.

The counts below were measured on the current practice API. A run should match them.

---

## Kinds of API testing

### Transport, CORS and headers (`config`)

- **Tests:** whether other websites can read the API using a visitor's login (CORS), and whether responses leak software details or miss protective headers.
- **How:** sends 3 ordinary GET requests, some with a foreign `Origin` header, and reads the response headers.
- **Perform:** press **Run**, then open the high finding and look at the `Access-Control-Allow-Origin` header in its evidence.
- **Expect:** 3 requests and 4 findings: 1 high, 1 medium, 2 low.

### Exposed files and diagnostics (`exposure`)

- **Tests:** whether files that should never be public can be read, such as `.env`, `.git` and debug pages.
- **How:** requests 12 well-known paths without logging in, and only reports a file if its content looks like the real thing.
- **Perform:** press **Run**, then open **Environment file publicly accessible**.
- **Expect:** 12 requests and 2 findings: 1 high (`.env`, with fake secrets) and 1 info (public API spec).

### Broken authentication (`authn`)

- **Tests:** routes that answer without a login, and tokens that can be forged.
- **How:** repeats protected requests with no token and with tampered copies of alice's token, including an unsigned one. It also tries a list of weak signing keys offline.
- **Perform:** press **Run**, then compare the two critical findings.
- **Expect:** 26 requests and 9 findings: 2 critical, 1 high, 6 low. The low ones are data-quality indicators that need human review.

### Cross-account access, or IDOR (`authz`)

- **Tests:** whether one user can read another user's data, and whether an ordinary user can reach admin functions.
- **How:** requests alice's and bob's records as each other, then compares the answers. It also tries admin routes as an ordinary user.
- **Perform:** press **Run**, then open a **Cross-account data access** finding and read its evidence.
- **Expect:** 11 requests and 4 findings: 3 high, 1 info.

### Input handling (`input`)

- **Tests:** whether unusual input changes how the server behaves: SQL errors, stack traces and reflected script.
- **How:** puts a quote character and a harmless marker into query parameters using GET requests only, so nothing is changed.
- **Perform:** press **Run**, then open **Possible SQL injection**.
- **Expect:** 21 requests and 3 findings: 1 high, 2 medium.

### Server-side data validation (`validation`)

- **Tests:** whether the server checks what it stores: malformed emails, wrong types, impossible numbers, and privileged fields such as `role` set by the client.
- **How:** sends fake records using reserved `.invalid` email addresses, only to endpoints opted in to writes.
- **Perform:** press **Run**, then open **Privileged fields can be set by the client**.
- **Expect:** 9 requests, all writes, and 8 findings: 1 high, 1 medium, 6 low.

### Signup, verification and enumeration (`identity`)

- **Tests:** access before an email is verified, duplicate accounts, weak passwords, and login answers that reveal who has an account.
- **How:** creates fake accounts, then compares the login answer for a known email with the answer for an unknown one.
- **Perform:** press **Run**, then open **Login responses reveal whether an account exists**.
- **Expect:** 6 requests, 5 of them writes, and 5 findings: 1 high, 3 medium, 1 low.

### Business logic (`logic`)

- **Tests:** requests that look valid but break the rules: negative quantities, prices chosen by the client, repeated orders.
- **How:** places fake orders with altered amounts, then sends the same order twice, one after the other.
- **Perform:** press **Run**, then open **The client decides the "price"**.
- **Expect:** 7 requests, all writes, and 6 findings: 2 high, 1 medium, 3 low.

### Rate limiting, before and after (`ratelimit`)

- **Tests:** whether the API pushes back on a client sending too many requests.
- **How:** sends a burst of at most 30 requests to an API with no limit, then to the same API limited to 5 requests per second.
- **Perform:** press **Run**, then use the phase buttons to compare.
- **Expect:**

| Phase | Requests | Findings |
| --- | --- | --- |
| 1. No rate limit | 30 | 1 medium |
| 2. Limit of 5 requests per second | 6, because the scan stops once it sees the limit | 0, and the retest shows 1 fixed |

### Fix and retest (`retest`)

- **Tests:** breakAPI's comparison between two scans, which shows whether a fix worked.
- **How:** scans the practice API, then scans it again with its main flaws patched.
- **Perform:** press **Run**, stay on phase 2, and read the **Retest** panel.
- **Expect:**

| Phase | Requests | Findings |
| --- | --- | --- |
| 1. Before the fix | 73 | 23 |
| 2. After the fix | 77 | 10, with the retest showing 13 fixed, 10 still open and 0 new |

The 10 still open are real: this patch doesn't cover everything, such as the `.env` file. That is the point of retesting.

### Full assessment (`full`)

- **Tests:** all nine test categories in one scan.
- **How:** runs each category in turn, with writes opted in, and rate limiting last.
- **Perform:** press **Run**, then press **Report** and read it from the top.
- **Expect:** 108 requests, 34 of them writes, 0 DELETE and 43 findings, 2 of them critical and 12 high.

---

## Safety controls

These examples show what stops breakAPI itself.

### Consent wall (`consent`)

- **Shows:** a scan with no valid authorization sends nothing.
- **How:** tries three scans: no authorization, an expired one, and a target outside the authorized scope.
- **Perform:** press **Run**, then read the reason on each phase.
- **Expect:** all 3 are **blocked**, and the target counts 0 requests each time.

### Request budget (`budget`)

- **Shows:** a scan stops itself at its limit.
- **How:** starts a broad scan with a budget of only 12 requests.
- **Perform:** press **Run**, then read the **Ended early** message.
- **Expect:** status **halted**, with exactly 12 requests counted by the target and 6 findings from the checks that got to run.

### Write protection (`writes`)

- **Shows:** nothing is written without two separate permissions: the authorization's write switch and an opt-in on each endpoint.
- **How:** runs the write-based checks three times with different permissions.
- **Perform:** press **Run**, then compare **target counted** on each phase.
- **Expect:**

| Phase | Writes the target counted | DELETE |
| --- | --- | --- |
| 1. Switch off, no opt-in | 0 | 0 |
| 2. Switch on, no opt-in | 0 | 0 |
| 3. Switch on, endpoints opted in | 21 | 0 |

---

## A suggested 10-minute showcase

1. **Full assessment:** show the range of findings and open the report.
2. **Cross-account access:** explain one finding through its evidence.
3. **Fix and retest:** show how a team confirms a fix.
4. **Consent wall** and **Write protection:** show that breakAPI holds itself back.
5. Sign in as a user and show a real project's authorization steps (below).

## Testing a real API

The lab never touches real systems. Real APIs need an account issued by an administrator.

**Administrator:**

1. On the first page, choose **Admin login**. On a new server this creates the first administrator, using the first-run setup token from the server log.
2. Go to **Admin → Issue a user account**, then enter the user's email. Type a password or leave it blank to generate one.
3. Copy the details and share them privately. They are shown only once.

**User:**

1. On the first page, choose **User login**.
2. Enter the email, password and setup token. All three are needed at every sign-in.
3. Create a project, then follow its steps: record the authorization, add the target, prove you control it, add test accounts and run a scan.

**How long access lasts:** 30 days at most. It ends sooner if the app restarts, and each account has one session at a time. An administrator can press **Issue again** for a new password, setup token and 30 days.

Only test APIs you own or have written permission to test.

## Running the practice API by hand

To explore on your own machine instead of using the lab, run the practice API separately. [TESTING.md](TESTING.md) and [TEST-SCENARIOS.md](TEST-SCENARIOS.md) cover this.

```bash
npm run demo                               # practice API on localhost:4010
npm start                                  # breakAPI on 127.0.0.1:7300
node testdata/seed.mjs --writes --scan     # a configured project and a running scan
```

Never expose the practice API to a network.
