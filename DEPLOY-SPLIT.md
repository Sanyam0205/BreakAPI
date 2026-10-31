# Deploy breakAPI: GitHub → Replit (backend demo) → Netlify (frontend)

This is a step-by-step runbook for putting breakAPI online as a **demo**, with the frontend on Netlify and the backend on Replit's free plan. For a real deployment, see [DEPLOY.md](DEPLOY.md); the Netlify half of this guide stays the same, you only change where the backend runs.

## How the pieces fit

```
Browser ──https──▶ Netlify  (serves public/: index.html, app.js, styles.css, fonts)
                      │
                      └── /api/*  /reports/*  /healthz  ──proxy──▶ Replit  (node src/main.js)
```

The browser only ever talks to the Netlify address. Netlify forwards the API paths to the backend ("rewrites"), so login cookies are first-party and no CORS setup is needed. Two settings tie the halves together:

| Setting | Where | Value |
| --- | --- | --- |
| `BACKEND_URL` | Netlify environment variable | the Replit address, `https://…`, no path |
| `BREAKAPI_PUBLIC_URL` | Replit Secret | the **Netlify** address, `https://….netlify.app` |

## Read this first: what "Replit free" means here

- **Demo only.** I could not confirm from Replit's own pages that the free plan can host a server. Their [deployment docs](https://docs.replit.com/cloud-services/deployments/about-deployments) say not to rely on data written to a *published* app's filesystem, and third-party guides say the free plan includes only a static deployment. So this guide runs breakAPI from the Repl's **workspace** (the Run button), not a published deployment.
- **It sleeps.** A workspace stops when idle. The first request after a pause fails or is slow until the Repl is awake. Netlify will show an error in the meantime.
- **Your data lives on the workspace disk**, which should survive sleeping but is not a backup. Treat it as disposable.
- **Not for real users or real credentials.** Use fake test accounts only.

When you want a real deployment, use the `Dockerfile` on a host with a persistent disk ([DEPLOY.md](DEPLOY.md)), then change only `BACKEND_URL` in Netlify and `BREAKAPI_PUBLIC_URL` on the backend.

---

## Part 1: GitHub

You need a GitHub account. The code is ready in `/Users/midnight/Documents/breakAPI`: a git repository is initialised and every file is **staged** but not committed. The `.gitignore` keeps out `data/` (your local database and encryption key), `.env`, `dist/` and large design screenshots.

### 1. Create the empty repository
1. Open <https://github.com/new>.
2. Repository name `breakapi`. Visibility **Public**.
3. **Do not** tick *Add a README*, *Add .gitignore* or *Choose a license*: the repo must start empty, or the first push is rejected.
4. **Create repository**. Keep the page open.

### 2. Choose your commit identity (do this once)
Commits carry a name and email that anyone can read in a public repo. GitHub gives you a private-forwarding address for this: *GitHub → Settings → Emails → "Keep my email addresses private"*, then copy the `ID+USERNAME@users.noreply.github.com` address shown there.

```bash
cd /Users/midnight/Documents/breakAPI
git config user.name  "Your Name"
git config user.email "ID+USERNAME@users.noreply.github.com"
```
(This sets it for this repository only.)

### 3. Commit
```bash
git status --short | head        # everything should be listed as "A" (added)
git commit -m "Initial commit: breakAPI 0.2.0"
```

### 4. Push
```bash
git remote add origin https://github.com/<USERNAME>/breakapi.git
git push -u origin main
```
GitHub no longer accepts your account password over HTTPS. When Git asks for a password, paste a **personal access token**: *GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate*, repository access *Only select repositories → breakapi*, permission *Contents: Read and write*. (Or set up an SSH key and use `git@github.com:<USERNAME>/breakapi.git`, or install the GitHub CLI with `brew install gh` and run `gh auth login`.)

### 5. Check and tidy up
1. Refresh the repo page: you should see `src/`, `public/`, `deploy/`, `netlify.toml`, the docs. You should **not** see `data/`, `.env`, `dist/`.
2. **Actions tab:** the `ci` workflow starts on the first push. It runs the tests on Node 22 and 24 and builds the Docker image. It has only run on macOS so far, so if it fails on Linux, open the failing step and send me the log.
3. **Settings → Code security → Private vulnerability reporting → Enable.** `SECURITY.md` tells people to use it.
4. **Choose a licence** (*Add file → Create new file → name it `LICENSE`* and pick a template). Until you do, nobody else has permission to use the code. I haven't chosen one for you.

---

## Part 2: The backend on Replit (demo)

### 1. Import the repository
1. <https://replit.com> → **Create App** → **Import from GitHub** → choose `breakapi` (you may need to authorise Replit to read your GitHub).
2. When it opens, in the **Shell** tab run `node -v`. Version 20 or newer should work; 22 is what breakAPI is tested on. If it is older, ask Replit's Dependencies/Modules tool for Node 22.

### 2. Set the Run command
Open the `.replit` file (enable *Show hidden files* if you can't see it) and make sure it contains this single line. It starts the demo API on `localhost:4010` and breakAPI beside it:

```
run = "sh -c 'node demo/vulnerable-api.js & exec node src/main.js'"
```

(The demo API listens only on `127.0.0.1`, so it is **not** reachable from the internet. It is deliberately insecure; never expose it.)

### 3. Add Secrets
Open **Tools → Secrets** (padlock) and add these. Do the last row **after** Part 3, when you know the Netlify address.

| Secret | Value | Why |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Replit can only reach a server listening on all interfaces |
| `BREAKAPI_SECRET_KEY` | the output of `node src/cli.js gen-key` run in the Shell | encrypts stored test credentials; keep a copy somewhere safe |
| `BREAKAPI_TRUST_PROXY` | `true` | read the visitor's IP and HTTPS flag forwarded by Netlify |
| `BREAKAPI_SIGNUP` | `closed` | nobody can create an account; you invite people |
| `BREAKAPI_ALLOW_LOCAL_TARGETS` | `true` | **demo only**: lets the app scan the bundled demo API on `localhost:4010`. Safe here only because you are the sole user |
| `BREAKAPI_ALLOW_PRIVATE_TARGETS` | `false` | keep other internal addresses off limits |
| `BREAKAPI_PUBLIC_URL` | `https://<your-site>.netlify.app` | **add after Part 3**; used for cookies and emailed links |

> The server runs in *development mode* (no `BREAKAPI_ENV=production`). In that mode email is **not sent**: messages are written to `data/outbox/` in the Repl. That is fine for a one-person demo, since the first administrator is created with a setup token and not an email. (Production mode requires an SMTP service; see [DEPLOY.md](DEPLOY.md).)

### 4. Run it and find the address
1. Click **Run**. The Console prints `breakAPI 0.2.0 (development) listening on 0.0.0.0:…`, the demo API's three test tokens, and a **setup token**. Copy the setup token.
2. Replit shows the app in a **Webview** with its own address, something like `https://<long-id>.<name>.replit.dev`. Click *open in a new tab* and copy that address: this is your `BACKEND_URL`. If the Webview shows nothing, open the Networking/Ports pane and make sure the port breakAPI printed (7300) is exposed.
3. **Check it from your own computer:**
```bash
curl https://<your replit address>/healthz
```
Expected: `{"ok":true,"version":"0.2.0"}`. If you get an HTML page instead, the Repl is asleep, still starting, or shows an interstitial; Netlify cannot proxy it until this returns that JSON. Wake it (open the Repl) and retry.

---

## Part 3: The frontend on Netlify

### 1. Create the site
1. <https://app.netlify.com> → **Add new project → Import an existing project → GitHub** → authorise → pick `breakapi`.
2. The build settings are read from `netlify.toml`: build command `node deploy/netlify-build.mjs`, publish directory `dist`, Node 22. Leave them.
3. Before deploying, open **Site configuration → Environment variables → Add a variable**: `BACKEND_URL` = the Replit address from Part 2 (`https://…`, no trailing path). The build fails with a clear message if it is missing, not `https`, or has a path.
4. **Deploy.** When it finishes, note the site address, e.g. `https://breakapi-demo.netlify.app`. (*Site configuration → Change site name* lets you pick a nicer one.)

### 2. Close the loop
Back in Replit, add the last Secret, `BREAKAPI_PUBLIC_URL` = the Netlify address (no trailing slash), then **Stop** and **Run** again so it takes effect.

If you ever change `BACKEND_URL`, redeploy: *Deploys → Trigger deploy → Clear cache and deploy site*.

---

## Part 4: First run and verification

1. Open `https://<your-site>.netlify.app/#/setup`.
2. Paste the **setup token** from the Replit Console, enter your name, email and a 12+ character password → *Create administrator*. You are signed in.
3. **Smoke test** (about 10 minutes):

| Check | Expect |
| --- | --- |
| `https://<site>/healthz` | the same `{"ok":true…}` JSON, served through Netlify |
| Browser dev tools → Application → Cookies → `bp_sid` | `HttpOnly`, `Secure`, `SameSite=Strict`, domain = the Netlify host |
| **Account → Sessions** | the IP is **your** public IP, not a Netlify or Replit address. If every session shows the same infrastructure IP, the proxy isn't passing the visitor IP, and IP-based rate limits are shared by all users (per-account limits still apply) |
| Create a project, record an authorization for `localhost:4010`, import `testdata/demo-manual.txt`, add alice and bob from the Console tokens | the standard project from [TEST-SCENARIOS.md](TEST-SCENARIOS.md) |
| Start a scan | about 90 requests, 18 findings |
| Open the **Report** | the report page loads with the dark theme, fonts and all sections |
| Admin → Invite a user | succeeds; the message appears in the Repl's `data/outbox/`, **not** in an inbox |

4. **Wake-up behavior:** leave it ~30 minutes, then reload the Netlify site. Expect an error until the Repl wakes; after it does, check you are still signed in and the project is still there (that confirms the workspace disk persisted).

---

## Limits to know about

| Limit | What you will see | Why |
| --- | --- | --- |
| Netlify gives up on a proxied request after **26 seconds** | A scan *start* that re-verifies several unreachable non-local hosts can fail with a 502. Scans themselves run in the background and are unaffected | [Netlify docs](https://docs.netlify.com/manage/routing/redirects/rewrites-proxies) |
| The Repl sleeps | Errors or slowness on the first request; a running scan can be interrupted (shown as *interrupted* on restart) | free workspace |
| Email isn't delivered | Verification, reset and invitation links sit in `data/outbox/` | no SMTP configured |
| `X-Forwarded-For` | If a proxy doesn't overwrite it, a visitor could spoof the IP used for IP-based limits; per-account limits are unaffected | `BREAKAPI_TRUST_PROXY=true` |
| One-user trust model | `BREAKAPI_ALLOW_LOCAL_TARGETS=true` is only safe because nobody else has an account | demo setting |

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| Netlify build fails: `BACKEND_URL is not set` / `must be https://` / `no path` | Set the variable exactly as `https://<host>` and redeploy |
| Netlify site loads but every API call returns 404/502 | Replit asleep, or `BACKEND_URL` wrong. Test `curl <BACKEND_URL>/healthz` |
| Sign-in appears to succeed but you are sent back to the login page | `BREAKAPI_PUBLIC_URL` is missing or doesn't exactly match the Netlify address (https, no trailing slash). The cookie or the Origin check is rejecting it. Fix and restart the Repl |
| `Cross-origin request refused` in a toast | Same cause as above |
| Emailed links point at the wrong site | `BREAKAPI_PUBLIC_URL` |
| Setup page says "setup token is not correct" | Use the token printed on the **latest** Run, or read `data/setup-token` in the Repl |
| The Repl won't expose a port | Confirm `HOST=0.0.0.0` is set, then check the Ports pane |
| `Scan blocked: … local targets are disabled` | `BREAKAPI_ALLOW_LOCAL_TARGETS` is `false`; the demo API needs it `true` |
| GitHub `git push` asks for a password and rejects it | Use a personal access token or SSH (Part 1, step 4) |
