# Status

Keep under about 60 lines. Finalized decisions go to `docs/decisions.md`; completed phases go to `docs/history.md`.

## Current focus
- Repository cleanup and Claude Code workflow setup (CLAUDE.md, docs/).

## Done recently
- Audit of the repo; CLAUDE.md corrected; `docs/` created (STATUS, history, decisions).
- `docs/Status.md` renamed to `docs/STATUS.md`; README Layout lists `docs/`.
- `EXAMPLES.md`, `DEPLOY-NETLIFY.md`, `DEPLOY-REPLIT.md` moved to `docs/`; links, `src/server.js`, `test/lab.test.js`, `.env.example`, `netlify.toml` and CLAUDE.md updated. The public URL `/EXAMPLES.md` is unchanged.
- All 32 relative markdown links and anchors (root and `docs/`) resolve.
- CLAUDE.md gained a "Done means" table (which docs to update per change type). `.claude/settings.json` + `.claude/hooks/docs-check.sh`: a Stop hook that blocks once when non-doc files changed but `docs/STATUS.md` did not. Pipe-tested; becomes live after `/hooks` or a restart.

## Next steps
1. Commit `.claude/` and the CLAUDE.md change; confirm in a fresh session that CLAUDE.md loads and the Stop hook fires.
2. Review and commit the cleanup (nothing is committed yet; `CLAUDE.md` and the new `docs/` files are untracked).
3. Resolve the open questions below.

## Known state
- Tests: 78 passing, 0 failing, 0 skipped (about 68s), re-run after the moves. The sim contract tests ran (`../breakAPI-sim` present).
- CI: Node 22 and 24, push and pull request; sim checked out into `.sim`, `BREAKAPI_REQUIRE_SIM=1` (contract tests fail rather than skip).
- Lint/format/type-check: none configured.
- Sibling repo `breakAPI-sim`: expected at `../breakAPI-sim`.

## Open questions
- Add a LICENSE and CONTRIBUTING.md? (depends on how the project is shared)
- A linter/formatter without adding runtime dependencies?
- Should the tracked `.impeccable/` files stay tracked?
- Legal review of `src/undertaking.js` before anyone relies on it.

## Known gaps
- The Stop hook only checks STATUS.md; the other "Done means" rows rely on following the table.
- Keep the README Layout in step with new folders (`docs/` added).
- `.impeccable/critique` and `surfaces` files embed a local `/Users/...` path (left as is by decision).
- `testdata/` has unreferenced hand-test fixtures (kept by decision).
- Older git history was only path-scanned for secrets, not content-scanned (content regex covered the 50 newest commits).
