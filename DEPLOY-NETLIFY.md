# Deploy breakAPI with one Replit project and a Netlify front end

This is for when you can run **only one Replit app**. The backend, including the simulation playground, runs in that one Repl. Netlify serves the pages and forwards the API calls.

```
Browser ──https──▶ Netlify   serves index.html, app.js, styles.css, fonts
                      │
                      └── /api/*  /reports/*  /healthz  /EXAMPLES.md ──proxy──▶ Replit (one Repl)
                                                                                 ├─ breakAPI  node src/main.js
                                                                                 └─ simulation (breakapi-sim repo,
                                                                                    cloned into ./sim, run inside
                                                                                    the same process)

Lab scans ──https──▶ Replit address /sim/s/<sandbox>/…     (the scanner goes straight to Replit, not through Netlify)
```

Netlify only runs short serverless functions and static files, so it **cannot** host breakAPI or the simulation themselves. It serves the pages and acts as the front door.

The two GitHub repos stay separate. The sim repo is cloned into a `sim/` folder inside the Repl, which breakAPI loads at startup. Updating either one is a `git pull`.

## Don't want Netlify? Use Replit alone

breakAPI serves its own pages, so one Repl is enough. Skip Part 3 and Part 4 and change three things in Part 2:

| Secret | Value without Netlify |
| --- | --- |
| `BREAKAPI_PUBLIC_URL` | the **Replit address** (the one you open in the browser) |
| `BREAKAPI_SIM_PUBLIC_URL` | leave it out; it defaults to `BREAKAPI_PUBLIC_URL` |
| `BREAKAPI_TRUST_PROXY` | still `true` (Replit sits in front of the app) |

Everything else (the clone of `sim/`, the other secrets, the checks in Part 6) is the same. Use the Replit address wherever Part 6 says "Netlify address". You lose only Netlify's CDN and its own domain, and you avoid its proxy time limit.

## Read this first

- **Replit free plan.** I could not confirm from Replit's own pages that the free plan can host a server that stays up. This guide runs breakAPI from the Repl's **workspace** (the Run button), which sleeps when idle. After a pause, the first request is slow or fails until the Repl is awake. Use it as a demo; use a Reserved VM or another always-on host when you need it to stay up (the README's [Running on your own server](README.md#running-on-your-own-server)).
- **Where the data lives.** breakAPI stores everything (the administrator, user records, projects, scans, the sessions file) in `data/db.json` on the Repl's disk, and it needs no database. A workspace's files normally survive the Repl sleeping and waking, so the administrator you create stays; I could not confirm this against Replit's own pages, so check it once with the "Leave it ~30 minutes" step in Part 6. A **published** deployment is different: Replit says not to rely on a published app's filesystem, and republishing replaces it. That is why this guide runs from the workspace. Either way, treat the data as a demo, not a record to keep, and use fake test accounts only.
- **Issued accounts end when the app restarts, by design.** Waking from sleep is a restart. The administrator is unaffected, and a regular user's record stays but their access ends, so an administrator uses **Admin → Issue again** to give them a new password and setup token. A database would not change this: it is a rule in the app (access lasts until the app stops running, or 30 days at most), not a storage limit.
- **One thing I could not test here:** a scan reaching the Repl's own public address from inside the Repl. It needs the Repl to call its own public URL. If your Repl cannot, the playground shows the sandbox as unreachable; see Troubleshooting.
- **Netlify gives up on a proxied request after about 26 seconds** ([Netlify docs](https://docs.netlify.com/manage/routing/redirects/rewrites-proxies)). Scans run in the background and are not affected.

---

## Part 1. GitHub: two repos

You should have both on GitHub already (`breakapi` and `breakapi-sim`). If not:

```bash
cd ~/Documents/breakAPI      && gh repo create breakapi     --private --source . --push
cd ~/Documents/breakAPI-sim  && gh repo create breakapi-sim --private --source . --push
```

Push the latest code in both. **Make the sim repo public** if you want the simplest setup. It holds no secrets (the control key never lives in the repo), and it is a training target by design. If it must stay private, you will clone it with a token in Part 2, step 4.

---

## Part 2. The backend on Replit (one Repl)

### 1. Create the Repl
**Create Repl → Import from GitHub** → `breakapi`.

### 2. `.replit`
Make sure the file says:

```toml
modules = ["nodejs-22"]
run = "node src/main.js"

[deployment]
run = ["node", "src/main.js"]

[[ports]]
localPort = 7300
externalPort = 80
```

### 3. Find the Replit address
Press **Run** once. In the Webview, choose **open in a new tab** and copy the address, something like `https://<long-id>.<name>.replit.dev`. This is your **Replit address**. Stop the Repl.

(If the Webview shows nothing, open the Networking / Ports pane and make sure port 7300 is exposed.)

### 4. Clone the simulation into the Repl
Open the **Shell** and run:

```bash
git clone https://github.com/<you>/breakapi-sim.git sim
ls sim/src/server.js        # must exist
```

Private sim repo: create a fine-grained GitHub token with **read-only Contents** access to `breakapi-sim` only, then run
`git clone https://<token>@github.com/<you>/breakapi-sim.git sim`.
The token is stored in `sim/.git/config` inside the Repl, so keep that token read-only and revoke it if the Repl is ever shared.

The `sim/` folder is in breakAPI's `.gitignore`, so it never ends up in the breakAPI repo.

### 5. Add Secrets
**Tools → Secrets.** Add every row. `BREAKAPI_PUBLIC_URL` is filled in during Part 4, once you know the Netlify address.

| Secret | Value | Why |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Lets Replit reach the app |
| `BREAKAPI_ENV` | `development` | Production mode requires SMTP email, which this setup doesn't have |
| `BREAKAPI_SECRET_KEY` | run `node src/cli.js gen-key` in the Shell and paste the output | Encrypts stored test credentials. Without it, a new key is generated whenever the data folder is lost, and stored credentials become unreadable |
| `BREAKAPI_TRUST_PROXY` | `true` | Reads the visitor's IP and the HTTPS flag forwarded by Netlify |
| `BREAKAPI_PUBLIC_URL` | `https://<your-site>.netlify.app` — **add in Part 4** | The address people use. Cookies and emailed links are built from it. No trailing slash |
| `BREAKAPI_SIM_EMBED_DIR` | `sim` | Turns the playground on, using the checkout from step 4 |
| `BREAKAPI_SIM_PUBLIC_URL` | the **Replit address** from step 3 | Where the scanner reaches sandboxes (`<this>/sim/s/<id>`). It must be the Replit address, **not** the Netlify one. No trailing slash, no path |
| `BREAKAPI_ALLOW_LOCAL_TARGETS` | `false` | Stops users scanning the server itself. Also the default on Replit; set it so it is explicit |
| `BREAKAPI_ALLOW_PRIVATE_TARGETS` | `false` | Stops users reaching private networks. Also the default on Replit |
| `BREAKAPI_LAB_DAILY_RUNS` | optional, default `300` | Server-wide cap on lab runs per UTC day |

You do **not** set `BREAKAPI_SIM_URL` or `BREAKAPI_SIM_CONTROL_KEY` in this setup. The embedded sim makes a fresh control key at every start and keeps it in memory. Setting those two as well as `BREAKAPI_SIM_EMBED_DIR` makes breakAPI refuse to start.

### 6. Run and check
Press **Run**. The console should show:

```
breakAPI 0.2.0 (development) listening on 0.0.0.0:7300 — ...
Lab playground: simulation embedded, sandboxes at https://<replit address>/sim/s/<id>
```

Copy the **setup token** printed after `No accounts exist yet` (you need it in Part 5). Then, from your machine:

```bash
R=https://<replit address>
curl $R/healthz            # {"ok":true,"version":"0.2.0"}
curl $R/sim/               # {"name":"breakAPI simulation",...}
curl $R/sim/_control/catalog   # {"error":{"code":"not_found",...}}   the control API is not reachable from outside
```

If `/healthz` returns an HTML page instead of JSON, the Repl is asleep or still starting. Open the Repl, wait, and retry.

---

## Part 3. The front end on Netlify

1. <https://app.netlify.com> → **Add new project → Import an existing project → GitHub** → authorise → pick `breakapi`.
2. Build settings are read from `netlify.toml`: build command `node deploy/netlify-build.mjs`, publish directory `dist`, Node 22. Leave them as they are.
3. Before the first deploy: **Site configuration → Environment variables → Add a variable**:

   | Variable | Value |
   | --- | --- |
   | `BACKEND_URL` | the **Replit address** (`https://…`, no path, no trailing slash) |

   The build fails with a clear message if it is missing, not `https`, or has a path.
4. **Deploy.** Note the site address, for example `https://breakapi-demo.netlify.app`. (**Site configuration → Change site name** lets you pick a nicer one.)

Netlify now serves the pages and forwards these paths to Replit: `/api/*`, `/reports/*`, `/healthz`, `/EXAMPLES.md`.

If you ever change `BACKEND_URL`, redeploy: **Deploys → Trigger deploy → Clear cache and deploy site**.

---

## Part 4. Connect the two

Back in Replit, add the last Secret:

| Secret | Value |
| --- | --- |
| `BREAKAPI_PUBLIC_URL` | the **Netlify address**, `https://<your-site>.netlify.app` (no trailing slash) |

**Stop** and **Run** again.

Why two different addresses? People use the Netlify one, so cookies and the origin check must match it (`BREAKAPI_PUBLIC_URL`). The scanner goes straight to Replit (`BREAKAPI_SIM_PUBLIC_URL`) so lab traffic doesn't pass through Netlify.

---

## Part 5. First administrator

1. Open `https://<your-site>.netlify.app/#/login/admin`.
2. Paste the setup token from the Replit console and create your administrator.

---

## Part 6. Check that everything works

Open the **Netlify** address in a private window.

| Check | Expect |
| --- | --- |
| Home page | **Try the demo lab**, **User login** and **Admin login**, with the disclaimer at the bottom centre |
| `https://<site>/healthz` | The same `{"ok":true…}` JSON, served through Netlify |
| Browser dev tools → Application → Cookies → `bp_sid` | `HttpOnly`, `Secure`, `SameSite=Strict`, domain = the Netlify host |
| **Admin** page settings | **Simulation** says `embedded, <replit host>/sim`; **Local targets** and **Private-network targets** both say refused |
| **Demo lab** | A **Simulation playground** pane above the examples, with 4 presets and 7 flaws |
| Playground: **Startup SaaS, leaky → Plant and scan** | **Planted vs detected: 4 of 4 planted found · 0 false alarms**. The sandbox address shown is on the Replit domain, ending `/sim/s/sbx_…` |
| On that run: **Hardened baseline → Retest** | Phase 2 has 0 findings and the retest lists them as fixed |
| **Demo lab → Full assessment → Run** | The built-in example: 108 requests and 43 findings |
| **Report** link on a run | Opens with a demo notice and the disclaimer. The `/EXAMPLES.md` link also opens |
| **Admin → Issue a user account**, then sign in with it in another private window | Works, and **Account** shows when access ends |
| **Account → Sessions** | The IP is **your** public IP, not a Netlify or Replit address. If every session shows the same infrastructure IP, the proxy is not passing the visitor IP, and IP-based rate limits are shared by everyone |
| Leave it ~30 minutes, then reload | An error until the Repl wakes; afterwards you are still signed in and the project is still there |

---

## A cleaner domain

The Netlify address is the only one you give to people. The Replit address is the backend; the browser never uses it, though it does appear in the lab (the sandbox address shown on a playground run).

| You want | Do this |
| --- | --- |
| A shorter free address | **Site configuration → Change site name**, giving `https://<name>.netlify.app` |
| Your own domain, such as `breakapi.example.com` | **Domain management → Add a domain** and follow the DNS instructions Netlify shows for it (a subdomain normally needs one `CNAME` record; an apex domain can use Netlify DNS). Netlify issues the HTTPS certificate itself once DNS is correct |

**After the address changes, update Replit.** Set `BREAKAPI_PUBLIC_URL` to the new address exactly (`https`, no trailing slash) and **Stop** and **Run**. Cookies, the cross-origin check and emailed links are all built from it, so until you do, sign-in loops back to the login page or fails with `Cross-origin request refused`. Use the new address everywhere from then on; the old one may stop signing in.

Nothing else changes: `BACKEND_URL` (Netlify) and `BREAKAPI_SIM_PUBLIC_URL` (Replit) point at the Replit address, which stays the same.

## Secrets reference

**Replit** (Tools → Secrets):

| Secret | Required | Value |
| --- | --- | --- |
| `HOST` | yes | `0.0.0.0` |
| `BREAKAPI_ENV` | yes | `development` |
| `BREAKAPI_SECRET_KEY` | yes | output of `node src/cli.js gen-key` |
| `BREAKAPI_TRUST_PROXY` | yes | `true` |
| `BREAKAPI_PUBLIC_URL` | yes | Netlify address |
| `BREAKAPI_SIM_EMBED_DIR` | for the playground | `sim` |
| `BREAKAPI_SIM_PUBLIC_URL` | with the line above | Replit address |
| `BREAKAPI_ALLOW_LOCAL_TARGETS` | recommended | `false` |
| `BREAKAPI_ALLOW_PRIVATE_TARGETS` | recommended | `false` |
| `BREAKAPI_LAB_DAILY_RUNS` | no | `300` |

**Netlify** (Site configuration → Environment variables):

| Variable | Required | Value |
| --- | --- | --- |
| `BACKEND_URL` | yes | Replit address |

There are no other secrets: no SMTP, no sim control key, no GitHub token (unless your sim repo is private; see Part 2, step 4).

---

## Updating

| What changed | Do this |
| --- | --- |
| The sim | In the Replit Shell: `git -C sim pull`, then **Stop** and **Run**. Live sandboxes are lost; the lab rebuilds a missing one on the next retest |
| breakAPI | Push to GitHub, then in the Repl's **Git** pane (or Shell: `git pull`), then **Stop** and **Run**. Restarting ends all issued access: use **Admin → Issue again** afterwards and tell your users |
| The front end | Push to `breakapi`; Netlify builds automatically |
| Moving the backend (new Replit address) | Change `BACKEND_URL` in Netlify and redeploy; change `BREAKAPI_SIM_PUBLIC_URL` in Replit and restart |

## Limits on this setup

| Limit | What it means |
| --- | --- |
| Sleeping | Both the sim and breakAPI go down together when the Repl sleeps. Netlify shows an error until it wakes. Sandboxes and lab runs are lost; the administrator and projects are kept (see "Where the data lives") |
| No Replit database | breakAPI does not use Replit's PostgreSQL. It keeps the data in a JSON file, which keeps the app free of dependencies. A database would help only a published deployment, whose disk is replaced when you republish |
| No email | Password resets and authorizer confirmations are written to a file on the instance, not delivered. Users should authorize their own projects, and an administrator uses **Issue again** when someone forgets a password |
| Real targets need proof | A real API must serve a verification token or publish it in DNS before it can be scanned |
| Playground scans are read-only | The sim has no write routes yet, so playground runs never send POST, PUT, PATCH or DELETE |
| Shared process | The sim runs in breakAPI's process. A heavy burst of playground traffic slows breakAPI itself; the daily cap bounds it |
| `X-Forwarded-For` | With `BREAKAPI_TRUST_PROXY=true`, a proxy that does not overwrite it would let a visitor spoof the IP used for IP-based limits. Per-account limits are unaffected |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Netlify build fails: `BACKEND_URL is not set` / `must be https://` / `no path` | Set it exactly as `https://<host>` and redeploy |
| The Netlify site loads but every API call returns 404 / 502 | The Repl is asleep, or `BACKEND_URL` is wrong. Test `curl <BACKEND_URL>/healthz` |
| Sign-in appears to succeed but you land back on the login page | `BREAKAPI_PUBLIC_URL` is missing or doesn't exactly match the Netlify address (https, no trailing slash). Fix it and restart the Repl |
| `Cross-origin request refused` | Same cause: `BREAKAPI_PUBLIC_URL` |
| breakAPI exits at startup, naming the sim | Read the message. Typical: `BREAKAPI_SIM_EMBED_DIR` is set without `BREAKAPI_SIM_PUBLIC_URL` (or `BREAKAPI_PUBLIC_URL`); the address is not https or has a path; or `BREAKAPI_SIM_URL` / `BREAKAPI_SIM_CONTROL_KEY` are also set |
| Console says `Lab playground: OFF, the embedded simulation did not start` | The line above it gives the reason, usually `sim/src/server.js` is missing. Re-run the clone from Part 2, step 4 |
| No playground pane on the lab page | The console line above says why. `Lab playground: off` means `BREAKAPI_SIM_EMBED_DIR` is not in the Secrets |
| A playground run fails with every request "skipped" or "could not be reached" | The Repl cannot reach its own public address. Check `BREAKAPI_SIM_PUBLIC_URL` is exactly the address in your browser's tab for the running Repl, and that `curl <that address>/sim/` works from your machine. If it works for you but not from inside the Repl, this setup cannot host the playground; use a separate sim app ([DEPLOY-REPLIT.md](DEPLOY-REPLIT.md)) |
| Admin login asks for a setup token again | The instance was replaced and its data is gone. Use the new token from the console |
| Random sign-outs | More than one instance is running. Run only one |
| `EADDRINUSE` | Two run commands are starting the app. Keep one |
