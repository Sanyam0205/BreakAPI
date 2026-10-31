---
version: 1
slug: "public-index-html"
primary_target: "public/index.html"
related_targets: ["public/app.js","public/styles.css","src/report.js","public/report.css"]
---

# Surface: breakAPI app (all screens) + scan report

Mode: Operate (app UI); the printable report is Read.

Audience: builders and small product teams checking APIs they own. Job: record consent, set scope, run a bounded scan, understand findings, fix, retest. Most important screen: scan results. Avoid: scary/alarmist walls of red; generic SaaS dashboard (stat cards, purple gradients).

User steer (pinned, 2026-10-29): "something more like a linux terminal, kernel based but easy for user to use and steer through." Pinned over the roll.

## Direction contract

THESIS: breakAPI behaves like a well-run Linux box: a scan is boot-time dmesg, a finding is a man page, the shell is a tmux session. Refuses the light stat-card security dashboard and the green-matrix hacker costume; every control stays a standard, labeled web control.

OWN-WORLD: tty charcoal ground, one-step-lighter panes divided by hairlines, light-gray ink with dim secondary; ANSI colours do jobs only: tmux green status bar is the shell, cyan is interaction and focus, red/yellow/blue/magenta are severities as bracketed tags. One self-hosted monospace family at a strict size scale; no rounded cards, 2px radius max.

STORY: the visitor sees where they are from the prompt-path breadcrumb, sees what's blocking from a readiness check printed like a boot checklist ([ OK ] / [FAIL]), runs a scan, watches the dmesg log, reads each finding as a man page, fixes, retests.

FIRST VIEWPORT: scan screen as a tmux split: prompt-path breadcrumb top; one-line scan header (status, requests bar, severity tally); left pane findings list as dmesg-style lines with [CRIT]/[HIGH] tags (j/k to move); right pane the selected finding's man page (NAME, SYNOPSIS, DESCRIPTION, EVIDENCE, FIX); the live log under it while running; tmux status bar fixed at bottom with windows 0-4 and scan state. Primary actions (Retest, Report) at the header's right.

FORM: Kernel Console, user-pinned terminal steer, replacing assigned candidate 7 (Marked Proof) by the user's re-roll steer. seed:60be2e0dc6e5d26b
Signature interaction: keyboard steering — number keys switch tmux windows, j/k move findings, Enter opens, ? shows the key map; all optional over normal clicks.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
