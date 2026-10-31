---
target: breakAPI app UI
total_score: 26
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 2
target_identity: "file:/Users/midnight/Documents/breakAPI/public/index.html"
target_fingerprint: "sha256:53fc6e96256a2b0452ff76095451da8ecb4498109f0b3b90381d95b60abbae72"
target_path: /Users/midnight/Documents/breakAPI/public/index.html
timestamp: 2026-10-29T20-09-54Z
slug: public-index-html
---
# Critique: breakAPI app (public/index.html, app.js, styles.css) + report

Method: dual-agent (A: design review sub-agent · B: detector sub-agent). Browser overlay unavailable (no browser automation tool exposed); existing CDP captures used.

## Design Health Score: 26/40 (Acceptable)
| # | Heuristic | Score | Key Issue |
|---|---|---|---|
| 1 | Visibility of System Status | 3 | Check states printed green "ok" beside HIGH findings read as "passed" |
| 2 | Match System / Real World | 2 | Terminal jargon (journalctl, systemctl, (7), base_url=, burst, synthetic writes) costs first-timers |
| 3 | User Control and Freedom | 3 | Native confirm() for destructive actions; Delete project on every tab |
| 4 | Consistency and Standards | 2 | Garbled time range; native datetime inputs ignore One Clock; DELETE row has Test checkbox; Remove styled unlike other destructive actions |
| 5 | Error Prevention | 3 | Strong gates; numeric controls lack inline validation/defaults |
| 6 | Recognition Rather Than Recall | 3 | Typed-name recall far from the name field |
| 7 | Flexibility and Efficiency | 4 | Full keyboard layer |
| 8 | Aesthetic and Minimalist Design | 2 | Authorization tab ~3,100px desktop / ~5,200px mobile |
| 9 | Error Recovery | 2 | Form errors are toasts only, no field-level messages |
| 10 | Help and Documentation | 2 | No inline "what each test sends"; no first-run guide |

## Design Specificity Verdict
Authored, not interchangeable: prompt-path breadcrumb, tmux windows, boot checklist, bracket tags, man-page findings. Scan screen ~9/10 specificity; setup screens (authorization, controls, accounts) ~5/10 — generic dark forms below the pane title. Detector: 1 advisory (repeating-stripes-gradient) = false positive (segmented meter specified by DESIGN.md).

## Priority Issues
1. [P1] Check states read as "passed" (scan header). Fixed in this run: neutral dim state with per-check finding counts.
2. [P1] Authorization tab is an undifferentiated wall; caveats after commit; 3 confirms duplicate undertaking clauses; new-record form fully expanded under an active record. Open → distill, layout.
3. [P2] Safety controls: ungrouped 11-field grid, no "defaults are fine" story, no inline validation. Open → layout, clarify.
4. [P2] Accessibility: page-wide aria-live, invalid listbox structure, selected finding out of view, dim Remove button, native confirm(). Fixed in this run.
5. [P3] Consistency drift: garbled time range, DELETE row checkbox fixed; native datetime format and Delete-project placement open → polish.

## Persona Red Flags
- Alex: import pane above endpoints after import; retype name to re-record; no bulk endpoint actions; lands on authorization tab when everything's set.
- Sam: (fixed) aria-live noise, listbox roles; placeholders look like content.
- Jordan: jargon; five equal tabs with no "do this first"; param=value assumes path-parameter knowledge.
- Builder (vibe coder): ~25 inputs before the first request; no lighter local path; Download JSON as a peer of Report; no "fix this first" pointer.

## Minor Observations
Man-page title wraps early; mobile tmux bar wraps to 2 rows; audit timestamps identical; local-only verification pane is verbose; no severity filter for 43 findings; report evidence fully open on screen.

## Questions to Consider
- What would a sudo-style "consent ceremony" look like in the kernel-console world?
- Should the scan header lead with the one thing to fix first?
- Does a local-only target need the same 25-field authorization as production?
