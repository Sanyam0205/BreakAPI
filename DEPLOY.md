# Deploying breakAPI

This guide is for running breakAPI on a server other people use. For a laptop, `npm start` is enough (see [README.md](README.md)).

## What you need

- A host with Docker (or Node.js 22+), a domain name, and ports 80/443 open.
- An SMTP account for outbound email (any provider: Postmark, SES, Mailgun, your own relay). breakAPI sends verification, password-reset, invitation and authorizer-confirmation emails. **Production refuses to start without it.**
- A legal review of the undertaking text in [src/undertaking.js](src/undertaking.js) before anyone relies on it.

## 1. Configure

```bash
cp .env.example .env
node src/cli.js gen-key        # or: openssl rand -base64 32   → BREAKAPI_SECRET_KEY
```

Fill in `.env`. In production (`BREAKAPI_ENV=production`) the server **refuses to start** unless these are set:

| Variable | Why |
| --- | --- |
| `BREAKAPI_PUBLIC_URL` | The `https://` address users reach. Used for emailed links (never the request's Host header, so links can't be poisoned) and to mark cookies `Secure`. |
| `BREAKAPI_SECRET_KEY` | 32-byte base64 key that encrypts stored test credentials. Keep it in your secret store, **not** in the data volume. Losing or changing it makes stored credentials unreadable (users re-enter them). |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `BREAKAPI_MAIL_FROM` | Email delivery. Port 465 uses implicit TLS, 587 uses STARTTLS. Credentials are never sent over an unencrypted connection to a remote host. |

Safe defaults you should only loosen deliberately:

| Variable | Production default | Notes |
| --- | --- | --- |
| `BREAKAPI_ALLOW_LOCAL_TARGETS` | `false` | `true` would let any user scan the breakAPI server itself (`localhost`, `127.x`, `::1`). |
| `BREAKAPI_ALLOW_PRIVATE_TARGETS` | `false` | `true` would let users reach `10.x`, `172.16–31.x`, `192.168.x`, `100.64/10` and `fc00::/7` from your network (a classic SSRF path into a VPC). Link-local and cloud-metadata addresses (`169.254.x`, `fe80::/10`, `fd00:ec2::254`) are **always** refused. |
| `BREAKAPI_SIGNUP` | `closed` | `open` lets anyone create an account; they still have to verify their email before creating projects or running tests. With `closed`, admins invite people. |
| `BREAKAPI_TRUST_PROXY` | `false` | Set `true` only behind a reverse proxy that the app is not reachable around. It makes breakAPI read client IPs (for rate limiting and audit) and the HTTPS flag from `X-Forwarded-*`. |
| `BREAKAPI_MAX_CONCURRENT_SCANS` | `4` | Server-wide cap on running scans. |
| `BREAKAPI_SESSION_HOURS` | `12` | Idle timeout. Sessions also end 7 days after sign-in, on password change/reset, and when an admin disables the user. |

## 2. Run

### Docker Compose (recommended)

Edit `deploy/Caddyfile` with your domain, then:

```bash
docker compose up -d
docker compose logs breakapi | grep -A2 "No accounts exist"
```

The log prints a one-time **setup token**. Open `https://<your-domain>/#/setup`, paste it, and create the first administrator. The token is deleted once used.

The Compose file runs breakAPI read-only, as a non-root user, with all Linux capabilities dropped, behind Caddy (automatic HTTPS). Data lives in the `breakapi-data` volume.

### Plain Node

```bash
BREAKAPI_ENV=production node --env-file=.env src/main.js
```

Put it behind a TLS-terminating proxy (Caddy, nginx, a load balancer) and set `BREAKAPI_TRUST_PROXY=true`.

## 3. First administrator and users

- **Setup token** (first run): as above.
- **Invite people:** Admin → *Invite a user*. They get a one-time link (72 h) to set their name and password; using it verifies their email.
- **Roles:** `admin` manages users and sees server settings and the system audit log. Admins do **not** automatically see other people's projects or findings: projects are visible only to their members (owner + members added on the project's Settings tab). Projects that predate accounts and were never assigned an owner appear under **Admin → Projects nobody owns**, where an admin can claim or delete them..
- **Recovery without email:** stop the server, then
  ```bash
  node src/cli.js create-admin --email you@example.com --name "Your Name"   # creates or promotes, signs out everywhere
  node src/cli.js reset-password --email someone@example.com
  node src/cli.js list-users
  ```
  The password comes from `BREAKAPI_ADMIN_PASSWORD` or a prompt. With Docker: `docker compose run --rm breakapi node src/cli.js …`.

## 4. Operate

- **Health:** `GET /healthz` (liveness, no auth) and `GET /readyz` (writes the data file; returns 500 if the volume isn't writable). The Docker image has a `HEALTHCHECK`.
- **Logs:** one JSON line per request on stdout (`method`, `path` without query string, `status`, `ms`, `user` id, `ip`). Secrets, cookies and request bodies are never logged.
- **Audit:** every project keeps its own audit log; the admin page shows the system audit log (sign-ins, failed sign-ins, invitations, role changes, disables, deletions).
- **Shutdown:** `SIGTERM` stops running scans (recorded as stopped with a reason), flushes the data file and exits. Scans interrupted by a crash are marked *interrupted* on the next start.
- **Backups:** back up the data volume (`db.json`) regularly. It contains hashed passwords, hashed session and link tokens, encrypted test credentials and all findings: treat backups as sensitive. Keep `BREAKAPI_SECRET_KEY` separately; without it, the encrypted credentials in a backup are unreadable (by design).
- **Upgrades:** stop, replace the image or code, start. Data migrations run at startup. Authorizations recorded before the undertaking existed are blocked until re-recorded.

## 5. Limits you should know about

- **Single process, single file.** The data store is one JSON file written atomically. That suits a team-sized deployment; it does not support several app instances sharing the same data, and every write rewrites the file. Running more than one replica against the same volume will lose data. Move to a database before scaling horizontally.
- **Rate limits are in memory.** They reset on restart and are per process.
- **Email is the identity anchor.** Account verification and authorizer confirmation prove control of an inbox, not legal authority (see [SECURITY.md](SECURITY.md)).
- **The demo API is never shipped.** `demo/`, `test/` and `testdata/` are excluded from the Docker image. Never deploy the demo.
