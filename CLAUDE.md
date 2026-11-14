# breakAPI: Claude Code Instructions

## Project
breakAPI is a consent-first API security checker. It scans APIs the user owns or is authorized to test for common weaknesses (broken access control, auth gaps, IDOR/BOLA, unsafe input handling, misconfiguration, missing rate limits) and explains each finding with evidence, impact and a fix.

It is a Node 22+ app with **zero dependencies and no build step**: a hand-written server and a vanilla JS single-page app. (`deploy/netlify-build.mjs` is a Netlify-only build step that assembles `dist/` for the front end; the app itself has no build.) A sibling repo, `breakAPI-sim`, provides the simulation backend for the demo lab.

## Project Context
Imported at the start of every session (project source of truth):

@PRODUCT.md @docs/STATUS.md

Read on demand (not imported, to keep every session lean):

- `README.md`: setup, configuration table, safeguards table, checks table, layout. Read before changing config, deployment behavior, or the list of checks.
- `SECURITY.md`: security model, SSRF protection, trust boundaries, residual risks. **Read before touching** auth, sessions, the guarded client, netguard, the demo lab, or the simulation.
- `DESIGN.md`: UI design system. Read before any change under `public/`.
- `docs/EXAMPLES.md`: demo lab examples and the real-API testing guide. Read before changing `src/lab.js` or the examples.
- `docs/DEPLOY-NETLIFY.md`, `docs/DEPLOY-REPLIT.md`: hosting guides. Read before changing deployment or environment variables.
- `docs/history.md`: completed work, newest first, with commit hashes. Read when you need to know when or how something was built.
- `docs/decisions.md`: finalized decisions and their reasons. Read before reopening a settled question.

If implementation details conflict with these documents, identify the conflict instead of silently changing product direction. If the documents contradict each other, report it.

## Design-tool state
`.impeccable/` is design-tool state and must not be hand-edited. Tracked: `config.json`, `design.json`, `critique/`, `surfaces/`. Ignored: `mocks/`, `review/`, `questions/`, `hook.cache.json`.

## Tech Stack (working decisions; change only after discussion)
- Node.js 22+, ES modules, **no runtime dependencies**, no build step.
- Single-process server with a JSON file data store (atomic writes).
- Vanilla JS single-page app in `public/`, self-hosted fonts, strict CSP (`default-src 'self'`): no inline styles or scripts, no third-party assets at runtime.
- Tests use the Node built-in test runner.
- Do not introduce a dependency, framework, bundler or database without explaining the trade-off and getting confirmation.

## Non-negotiable Constraints
These come from the product principles in PRODUCT.md. Never weaken them without explicit instruction.

1. **Permission before probing.** No request is sent until an authorization is recorded, the host is in scope and (for non-local hosts) control is verified. The consent flow is never skippable or buried.
2. **All scan traffic goes through the guarded client** (`src/client.js`). Never open sockets or call `fetch` for scan targets from anywhere else.
3. Never send DELETE. Write methods (POST, PUT, PATCH) need the authorization's write switch and a per-endpoint opt-in, and use synthetic data only.
4. Hard ceilings on budgets, rate and duration hold even if stored controls are edited. Redirects are not followed. Wildcard scopes are not accepted.
5. Hosted mode refuses localhost, private-network and cloud-metadata targets unless explicitly allowed. Link-local and metadata addresses are always refused.
6. Every scan request carries `X-BreakAPI-Scan: <id>`.
7. Never claim an API is "secure". Absence of findings is not proof. Mark low-confidence findings as such.
8. Never fabricate customers, testimonials, benchmarks or pricing.
9. Secrets: test credentials stay encrypted (AES-256-GCM) and masked in logs and evidence. Never log secrets, cookies or request bodies. Never commit `.env`, `data/` or keys. (`.vscode/` and `.DS_Store` are already in `.gitignore`.)
10. The owner stays in control: pause, stop and revoke are always visible and immediate.
11. Do not weaken CSP, session handling, rate limiting, or the SSRF protection in `src/netguard.js`.
12. The practice API in `demo/` is deliberately vulnerable. Never bind it to a network-facing address, and never "fix" planted flaws in `demo/` or `breakAPI-sim` without being asked.
13. Brand: name is **breakAPI**; tagline "How secure is your API?"; the closing line in PRODUCT.md is fixed.

## Coding Preferences
- Simple, modular, readable code. Small focused functions. One module per check category in `src/checks/`.
- Follow the conventions of the existing project. Do not rewrite working code unnecessarily and do not over-engineer.
- Validate and bound all input at the server boundary. Fail closed.
- Keep scanning logic, HTTP API, storage and UI cleanly separated.
- Write tests for important behavior, especially safety controls. A new check needs a test against the demo API (finds the flaw) and the fixed demo (reports nothing).
- Default to plain language in the UI, with expert detail one step away.

## Development Rules
- Inspect the existing repository before creating or modifying files. Do not assume a structure exists.
- Implement incrementally. No placeholder modules.
- Do not silently add dependencies or system software. Tell me what is missing and let me install it.
- Explain significant architectural changes before implementing them.
- Add or update tests when changing core behavior, and run the relevant tests afterward.
- Do not claim a feature is complete without verifying it.
- Keep documentation in sync with behavior. If you add an environment variable, update `.env.example` and the README configuration table. If you add a check, update the README checks table.
- After each task, update `docs/STATUS.md` (keep it under about 60 lines). Move finalized decisions into `docs/decisions.md` or the relevant doc instead of letting them accumulate there.
- After each completed phase, move its entry from `docs/STATUS.md` to `docs/history.md` (newest first, a few lines, with the commit hash).
- Commit only when I ask. Never push, force-push, or change git remotes unless I explicitly ask.
- Never kill processes by name (`pkill node`, `killall`, `taskkill /IM`). Kill only by PID of a process you started yourself.
- Never run the demo API or breakAPI on `0.0.0.0` for experiments. For manual runs set `BREAKAPI_DATA` to a temporary folder so the real `data/` is untouched.
- Never scan a target I haven't said I own or am authorized to test. Local demo targets only unless told otherwise.

## Commands
Run from the repository root (Node 22+):

- `npm start`: run breakAPI on http://127.0.0.1:7300 (prints a one-time setup token for the first admin)
- `npm run demo`: deliberately vulnerable practice API on http://localhost:4010 (local only)
- `npm test`: full test suite (sim contract tests skip locally unless `../breakAPI-sim` exists or `BREAKAPI_SIM_DIR` is set; CI sets `BREAKAPI_REQUIRE_SIM=1`, so there they fail instead of skipping)
- `npm run admin -- <create-admin|reset-password|list-users|gen-key>`: operator CLI
- CI (`.github/workflows/ci.yml`) runs `npm test` on Node 22 and 24 for pushes and pull requests, with `breakapi-sim` checked out into `.sim`.
- `node testdata/seed.mjs --scan`: seed a configured project and start a scan (both servers must be up)

Lint, format and type-check commands: none configured yet. If one is added, record it here.

## Done means
A task is not finished until the docs for what it touched are updated in the same change. Always update `docs/STATUS.md`; then add whatever applies:

| Change | Also update |
| --- | --- |
| New or changed environment variable or config default | `.env.example` and the README configuration table |
| New or changed check | README checks table, `docs/EXAMPLES.md` if an example covers it |
| Change to auth, sessions, netguard, the guarded client, the lab or the sim | `SECURITY.md` |
| Change under `public/` (UI, tokens, components) | `DESIGN.md` |
| Lab examples or the real-API guide | `docs/EXAMPLES.md` (and its test in `test/lab.test.js`) |
| Deployment, hosting or Netlify/Replit behavior | `docs/DEPLOY-NETLIFY.md`, `docs/DEPLOY-REPLIT.md`, `netlify.toml` |
| New, moved or removed file or folder | README Layout section, plus every link to it |
| A decision that settles an open question | `docs/decisions.md`, and remove it from STATUS open questions |
| A finished phase | move its entry from STATUS to `docs/history.md` (hash after the commit exists) |

Also run `npm test` and record the result in STATUS "Known state". A Stop hook (`.claude/hooks/docs-check.sh`) blocks once when code or config changed but `docs/STATUS.md` did not; it cannot check the other rows, so use this table.

## Scope Control
Build thin vertical slices and widen. Do not jump ahead to hosted-SaaS features (billing, public sign-up, multi-replica storage) while the core scanner, consent flow and report quality are incomplete. The JSON single-file store is a known limit; moving to a database is an architecture decision, not a drive-by change.

## Open Questions
Do not make these decisions silently. When a decision is needed: explain the options and trade-offs, recommend one, and ask for confirmation if it materially changes architecture or product scope. Currently open items are listed in `docs/STATUS.md`.

## Working Style
Before implementing a major feature: explain what will be built, identify the relevant modules, state assumptions, and define acceptance criteria.

After implementation: summarize files changed, explain important design decisions, report tests run and their results, and list known limitations.

## Session Start Checklist
1. Read the imported files (PRODUCT.md, docs/STATUS.md).
2. Run `git status` and `git log -5 --oneline` and compare with STATUS.md. Report any mismatch.
3. Read the on-demand docs relevant to the task before touching code.
4. Confirm the plan, then implement.