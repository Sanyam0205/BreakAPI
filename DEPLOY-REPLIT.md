# Run breakAPI on Replit

Replit runs the whole app: the API, the pages and the demo lab. For a host where your data is safe across restarts, use [DEPLOY.md](DEPLOY.md) instead.

## Read this first: how long things last

Your rule is that a user's access lasts until the app stops running, or 30 days at most. **Whether it reaches 30 days depends on the deployment type**, because a published Replit app loses its data when its instance is replaced.

| Deployment type | What happens | Effect on breakAPI |
| --- | --- | --- |
| **Autoscale** (what you have now) | Stops when idle and starts a fresh instance on the next visit | Every account, including the admin, can disappear after a quiet spell. You get a new first-run setup token. Fine for the demo lab, but won't hold 30-day accounts |
| **Reserved VM** | Keeps one instance running | Accounts last until you republish or the instance restarts, up to the 30 days. **Use this if you are issuing accounts.** It is a paid option, so check Replit's current pricing |

Publishing again always restarts the app, which ends all issued access. Replit's [deployment docs](https://docs.replit.com/cloud-services/deployments/about-deployments) say not to rely on a published app's filesystem.

## 1. Configure the Repl

Your `.replit` should run the app the same way in the workspace and when published:

```toml
run = "node src/main.js"

[deployment]
run = ["node", "src/main.js"]
```

## 2. Add Secrets

In **Tools → Secrets**:

| Secret | Value | Why |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Lets Replit reach the app |
| `BREAKAPI_ENV` | `development` | Production mode requires SMTP email, which this setup doesn't have |
| `BREAKAPI_SECRET_KEY` | run `node src/cli.js gen-key` | Encrypts stored test credentials |
| `BREAKAPI_TRUST_PROXY` | `true` | Replit sits in front of the app |
| `BREAKAPI_PUBLIC_URL` | `https://break-api--SanyamSingh6.replit.app` | Marks cookies `Secure` and builds links. No trailing slash |
| `BREAKAPI_ALLOW_LOCAL_TARGETS` | `false` | Stops users scanning the server itself. The demo lab still works |
| `BREAKAPI_ALLOW_PRIVATE_TARGETS` | `false` | Stops users reaching private networks |

You can delete `BREAKAPI_SIGNUP` if you set it. It no longer does anything, because public sign-up has been removed.

## 3. Publish

1. Pull the latest code into the Repl from GitHub.
2. Choose **Publish** and pick the deployment type from the table above.
3. If you stay on Autoscale, set the maximum number of instances to **1**. Instances don't share data, so more than one causes random sign-outs.
4. Check it's running:

```bash
curl https://break-api--SanyamSingh6.replit.app/api/healthz
```

Use `/api/healthz`. On Replit, Google answers plain `/healthz` itself with a 404.

## 4. First administrator

1. In the deployment **Logs**, find the line after `No accounts exist yet` and copy the first-run setup token.
2. Open the app and choose **Admin login**.
3. Paste the token and create your administrator.

## 5. Check it works

| Check | Expect |
| --- | --- |
| Open the app in a private window | **Try the demo lab**, **User login** and **Admin login**, with the disclaimer at the bottom centre |
| **Demo lab → Full assessment → Run** | 108 requests and 43 findings |
| **Report** on that run | The report opens with a demo notice and the disclaimer |
| **Admin → Issue a user account** | Shows the password and setup token once |
| Sign in with those in another private window | Works, and **Account** shows when access ends |

Then read [EXAMPLES.md](EXAMPLES.md) for what to run and show.

## Limits on this setup

| Limit | What it means |
| --- | --- |
| No email | Password resets and authorizer confirmations are written to a file on the instance instead of being delivered. Users should authorize their own projects, and an administrator uses **Issue again** when someone forgets a password |
| Real targets need proof | A real API must serve a verification token or publish it in DNS before it can be scanned |
| In-memory limits | Rate limits and lab runs reset when the instance restarts |

## Updating

Push to GitHub, pull in the Repl and publish again. **Publishing ends all issued access and may reset accounts**, so use **Issue again** or re-create them afterwards, and tell your users.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Admin login asks for a setup token again | The instance was replaced and its data is gone. Use the new token from the logs |
| Random sign-outs | More than one instance is running. Set the maximum to 1 |
| `Cross-origin request refused` or sign-in loops | `BREAKAPI_PUBLIC_URL` doesn't exactly match the address in the browser |
| The server exits at startup | `BREAKAPI_ENV` is missing, so `NODE_ENV=production` turned on production mode. Set it to `development` |
| `EADDRINUSE` | Two run commands are starting the app. Keep one |
| A user's "access ended when the app restarted" | Expected after a restart. Use **Admin → Issue again** |
