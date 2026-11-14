# History

Completed work, newest first. Seeded from `git log` (dates are commit dates).

## Repo cleanup and docs workflow (2026-11-15)
- Added CLAUDE.md, `docs/STATUS.md`, `history.md`, `decisions.md`.
- Moved `EXAMPLES.md`, `DEPLOY-NETLIFY.md`, `DEPLOY-REPLIT.md` into `docs/`; `/EXAMPLES.md` URL unchanged.
- Added CLAUDE.md "Done means" checklist and a project Stop hook (`.claude/hooks/docs-check.sh`) that blocks once if code changed without a `docs/STATUS.md` update.
- Docs commit: `f19e373` (Docs maintenance); hook and checklist not committed yet.

## Hosted deployment: Replit backend, Netlify front end (2026-11-05)
- `c1f40bc` Deployment to Replit and Netlify changes
- `6aa4a5c` Front end to Netlify and backend to Replit

## CI and Node 24 (2026-11-05)
- `650bd04` Run tests with an explicit glob (Node 24)

## Lab playground on the simulation backend (2026-11-05)
- `01b46ef` Lab playground on the simulation backend; hosted-safe defaults

## Invite-only accounts, demo and real modes (2026-10-31)
- `ba71a88` Demo and Real invite only API

## Initial build (2026-10-31)
- `7a2f5b9` BreakAPI: scanner, guarded client, consent flow, UI, demo API
