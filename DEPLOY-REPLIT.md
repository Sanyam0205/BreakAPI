# Run breakAPI and its simulation on Replit

breakAPI is deployed as **two separate Replit apps, from two GitHub repos**:

| Repo | Replit app | What it does |
| --- | --- | --- |
| `breakapi` (this repo) | e.g. `https://break-api--<you>.replit.app` | The scanner, the pages, the demo lab and issued accounts |
| `breakapi-sim` | e.g. `https://breakapi-sim--<you>.replit.app` | The simulation backend: per-visitor sandboxes of a deliberately vulnerable SaaS API |

```
visitor ──▶ breakAPI (Repl 1) ──control API, shared key──▶ breakapi-sim (Repl 2)
                     └──────── scans /s/<sandbox> over https ──────────┘
```

The lab works without the sim: the built-in examples run against a practice API inside breakAPI. The sim adds the **Simulation playground**, where visitors choose which flaws to plant, then scan, score and retest.

For a host where your data is safe across restarts, see [DEPLOY.md](DEPLOY.md).

---

## Step 0. Put both repos on GitHub

The two folders sit side by side on your machine:

```
Documents/breakAPI       → github.com/<you>/breakapi
Documents/breakAPI-sim   → github.com/<you>/breakapi-sim
```

With the GitHub CLI (`gh auth login` first):

```bash
cd ~/Documents/breakAPI
git push                                         # breakapi already has a remote; otherwise:
# gh repo create breakapi --private --source . --push

cd ~/Documents/breakAPI-sim
gh repo create breakapi-sim --private --source . --push
```

Without the CLI, create an empty repo named `breakapi-sim` on github.com, then:

```bash
cd ~/Documents/breakAPI-sim
git remote add origin https://github.com/<you>/breakapi-sim.git
git push -u origin main
```

**CI:** breakAPI's workflow checks out `<you>/breakapi-sim` to run the contract tests between the two.
- **Private sim repo:** create a fine-grained token with read access to `breakapi-sim`, and add it to the **breakapi** repo as the Actions secret `SIM_REPO_TOKEN`.
- **Different name or owner:** set the Actions variable `SIM_REPOSITORY` (for example `someone/my-sim`).

## Step 1. Generate the shared control key

breakAPI uses this key to create and delete sandboxes on the sim. Both apps must hold the same value. Generate it once, on your machine or in any Replit Shell:

```bash
openssl rand -base64 32
# or: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Keep it somewhere safe for the next two steps. Never commit it.

---

## Step 2. Deploy the simulation (Repl 2)

1. **Create the Repl:** in Replit, choose **Create Repl → Import from GitHub**, pick `breakapi-sim`, and let it import. The repo includes a `.replit` file that sets the run command, the port (4020) and the deployment type.
2. **Add Secrets** (**Tools → Secrets**):

   | Secret | Value |
   | --- | --- |
   | `SIM_CONTROL_KEY` | the key from Step 1 |
   | `SIM_PUBLIC_URL` | leave it out for now; you add it after publishing (step 5) |

3. **Try it in the workspace:** press **Run**. The console shows `breakAPI simulation on http://localhost:4020`, and the webview shows `{"name":"breakAPI simulation", …}`.
4. **Publish:** choose **Publish** (Deployments).

   | Deployment type | Effect | Recommendation |
   | --- | --- | --- |
   | **Reserved VM** | One instance stays up, so sandboxes survive between a scan and its retest | **Recommended.** The smallest size is enough. Paid; check Replit's pricing |
   | **Autoscale** | Sleeps when idle and loses every sandbox | Works, because breakAPI rebuilds a missing sandbox from its seed on retest. **Set Max instances to 1**: sandboxes are in memory, so a second instance would not know them |

   The `.replit` asks for a Reserved VM (`deploymentTarget = "gce"`). Change it in the Publish pane if you want Autoscale.

5. **Set the public URL:** once it is published, copy the URL Replit shows (`https://breakapi-sim--<you>.replit.app`). Add it as the secret `SIM_PUBLIC_URL`, with no trailing slash, and publish again.
6. **Check it** from your machine:

   ```bash
   SIM=https://breakapi-sim--<you>.replit.app
   KEY='<the key from Step 1>'
   curl $SIM/                                                           # {"name":"breakAPI simulation",...}
   curl -H "Authorization: Bearer $KEY" $SIM/_control/catalog           # the catalog: 7 vulns, 4 presets
   curl -H "Authorization: Bearer wrong" $SIM/_control/catalog          # 401: the key is enforced
   ```

   Use `/` rather than `/healthz` for checks. On `replit.app`, Google's front end answers `/healthz` itself.

**The sim refuses to start** when deployed without `SIM_CONTROL_KEY`, or with a key shorter than 24 characters. If the deployment logs show that, fix the secret and publish again.

---

## Step 3. Deploy breakAPI (Repl 1)

If you already have the breakAPI Repl, pull the latest code into it (**Git** pane → **Pull**) and skip to the secrets.

1. **Create the Repl:** **Create Repl → Import from GitHub**, pick `breakapi`.
2. **`.replit`:** this repo does not ship one, because an existing Repl already has its own. Make sure yours says:

   ```toml
   modules = ["nodejs-22"]
   run = "node src/main.js"

   [deployment]
   run = ["node", "src/main.js"]

   [[ports]]
   localPort = 7300
   externalPort = 80
   ```

3. **Add Secrets** (**Tools → Secrets**):

   | Secret | Value | Why |
   | --- | --- | --- |
   | `HOST` | `0.0.0.0` | Lets Replit reach the app |
   | `BREAKAPI_ENV` | `development` | Production mode requires SMTP email, which this setup doesn't have |
   | `BREAKAPI_SECRET_KEY` | run `node src/cli.js gen-key` in the Shell | Encrypts stored test credentials. Without it, a new key is generated on every fresh instance and stored credentials become unreadable |
   | `BREAKAPI_TRUST_PROXY` | `true` | Replit sits in front of the app |
   | `BREAKAPI_PUBLIC_URL` | `https://break-api--<you>.replit.app` | Marks cookies `Secure` and builds links. No trailing slash |
   | `BREAKAPI_ALLOW_LOCAL_TARGETS` | `false` | Stops users scanning the server itself. On Replit this is already the default; setting it makes it explicit |
   | `BREAKAPI_ALLOW_PRIVATE_TARGETS` | `false` | Stops users reaching private networks. Also the default on Replit |
   | `BREAKAPI_SIM_URL` | `https://breakapi-sim--<you>.replit.app` | The sim from Step 2: bare origin, https, no trailing slash |
   | `BREAKAPI_SIM_CONTROL_KEY` | the key from Step 1 | Must equal the sim's `SIM_CONTROL_KEY` |
   | `BREAKAPI_LAB_DAILY_RUNS` | optional, default `300` | Server-wide cap on lab runs per UTC day, since each playground run sends real traffic to the sim |

   breakAPI **refuses to start** in these cases:
   - only one of the two `BREAKAPI_SIM_*` secrets is set;
   - the sim URL is not https;
   - the sim URL has a path;
   - the key is shorter than 24 characters.

   The deployment logs name the problem.

4. **Publish:**

   | Deployment type | What happens | Effect on breakAPI |
   | --- | --- | --- |
   | **Autoscale** | Stops when idle and starts a fresh instance on the next visit | Every account, including the admin, can disappear after a quiet spell, and you get a new first-run setup token. Fine for the demo lab, but won't hold 30-day accounts. **Set Max instances to 1**: lab runs and sessions are in memory |
   | **Reserved VM** | Keeps one instance running | Accounts last until you republish or the instance restarts, up to the 30 days. **Use this if you are issuing accounts.** Paid; check Replit's pricing |

   Publishing again always restarts the app, which ends all issued access. Replit's [deployment docs](https://docs.replit.com/cloud-services/deployments/about-deployments) say not to rely on a published app's filesystem.

5. **Check the logs:** the deployment **Logs** should show:

   ```
   breakAPI 0.2.0 (development) listening on 0.0.0.0:7300 — https://break-api--<you>.replit.app
   Lab playground: simulation at breakapi-sim--<you>.replit.app
   ```

   A `Lab playground: off` line means the two `BREAKAPI_SIM_*` secrets are missing from the deployment.

6. **Health check:**

   ```bash
   curl https://break-api--<you>.replit.app/api/healthz
   ```

## Step 4. First administrator

1. In breakAPI's deployment **Logs**, find the line after `No accounts exist yet` and copy the setup token.
2. Open the app, choose **Admin login**, paste the token and create your administrator.

---

## Step 5. Check that everything works

| Check | Expect |
| --- | --- |
| Open breakAPI in a private window | **Try the demo lab**, **User login** and **Admin login**, with the disclaimer at the bottom centre |
| **Demo lab** | A **Simulation playground** pane above the examples, with 4 presets and 7 flaws |
| Playground: **Startup SaaS, leaky → Plant and scan** | **Planted vs detected: 4 of 4 planted found · 0 false alarms**, plus the sandbox address on the sim's domain |
| On that run: choose **Hardened baseline → Retest** | Phase 2 has 0 findings and the retest lists them as fixed |
| **Report** on a playground run | It says the target was the simulation backend and that no real system was contacted |
| **Demo lab → Full assessment → Run** | The built-in example: 108 requests and 43 findings |
| **Admin → Issue a user account** | Shows the password and setup token once |
| **Admin** page settings | **Simulation** shows the sim's host, and **Local targets** and **Private-network targets** both say refused |

---

## Updating

| What changed | Do this |
| --- | --- |
| The sim | Push to `breakapi-sim`, then in Repl 2 pull and publish. Live sandboxes are lost; breakAPI rebuilds them on the next retest |
| breakAPI | Push to `breakapi`, then in Repl 1 pull and publish. **Publishing ends all issued access and may reset accounts**: use **Issue again** or re-create them afterwards, and tell your users |
| Rotating the control key | Generate a new one, set it in **both** Repls, and publish the sim first, then breakAPI. In between, the playground shows "not available"; nothing else is affected |

## Limits on this setup

| Limit | What it means |
| --- | --- |
| No email | Password resets and authorizer confirmations are written to a file on the instance instead of being delivered. Users should authorize their own projects, and an administrator uses **Issue again** when someone forgets a password |
| Real targets need proof | A real API must serve a verification token or publish it in DNS before it can be scanned. Only the sim is exempt, and only for lab playground runs the server builds itself |
| In-memory state | Rate limits, lab runs and sandboxes reset when an instance restarts |
| Playground scans are read-only | The sim has no write routes yet, so playground runs never send POST, PUT, PATCH or DELETE |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| The lab has no playground pane | `Lab playground: off` in the logs means the `BREAKAPI_SIM_*` secrets are not in the deployment. If they are set, the sim is unreachable: open the sim URL in a browser |
| "The simulation backend is not available right now" | Either the sim is asleep or down (open its URL), or the two keys differ. A wrong key looks like an outage on purpose, so check that both secrets hold the same value |
| breakAPI exits at startup | Read the logs. It names the sim setting, or says `BREAKAPI_ENV` is missing (then `NODE_ENV=production` turned on production mode; set it to `development`) |
| The sim exits at startup | `SIM_CONTROL_KEY` is missing or shorter than 24 characters |
| Retests sometimes rebuild the sandbox | Expected on Autoscale, or after the sim restarts. Use a Reserved VM for the sim to avoid it |
| Admin login asks for a setup token again | breakAPI's instance was replaced and its data is gone. Use the new token from the logs |
| Random sign-outs, or a lab run "no longer available" right after starting | More than one breakAPI instance is running. Set Max instances to 1 |
| `Cross-origin request refused` or sign-in loops | `BREAKAPI_PUBLIC_URL` doesn't exactly match the address in the browser |
| `EADDRINUSE` | Two run commands are starting the app. Keep one |
