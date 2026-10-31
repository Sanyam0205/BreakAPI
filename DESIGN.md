---
name: breakAPI
description: How secure is your API? A kernel console for checking the APIs you own.
colors:
  tty-charcoal: "#111214"
  pane: "#17191c"
  pane-raised: "#1e2125"
  hairline: "#2b2f34"
  hairline-strong: "#3a3f45"
  ink: "#dadde1"
  dim: "#9ba2aa"
  shell-green: "#4ee08a"
  shell-green-ink: "#07130c"
  signal-cyan: "#62d6e8"
  signal-cyan-ink: "#061316"
  selection-wash: "rgba(98, 214, 232, 0.11)"
  sev-red: "#ff7070"
  sev-magenta: "#f08ce0"
  sev-yellow: "#f0c45a"
  sev-blue: "#84adff"
  print-paper: "#ffffff"
  print-ink: "#111111"
  print-dim: "#555555"
  print-line: "#cccccc"
  print-panel: "#f3f3f3"
  print-green: "#137a3a"
  print-cyan: "#0b6e7d"
  print-red: "#b3261e"
  print-magenta: "#9b1f86"
  print-yellow: "#8a6100"
  print-blue: "#1f4fbf"
typography:
  display:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "20px"
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: "-0.015em"
  title:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "16px"
    fontWeight: 700
    lineHeight: 1.25
  body:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.6
    fontFeature: "\"liga\" 0, \"calt\" 0"
  body-ui:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "0.06em"
rounded:
  hairline: "2px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  pane-gap: "20px"
  lg: "24px"
  xl: "32px"
components:
  button:
    backgroundColor: "{colors.pane-raised}"
    textColor: "{colors.ink}"
    typography: "{typography.body-ui}"
    rounded: "{rounded.hairline}"
    padding: "7px 14px"
  button-hover:
    backgroundColor: "#262a2f"
  button-primary:
    backgroundColor: "{colors.shell-green}"
    textColor: "{colors.shell-green-ink}"
    rounded: "{rounded.hairline}"
    padding: "7px 14px"
  button-primary-hover:
    backgroundColor: "#6ae99e"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.sev-red}"
    rounded: "{rounded.hairline}"
    padding: "7px 14px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.dim}"
    rounded: "{rounded.hairline}"
    padding: "7px 14px"
  button-sm:
    padding: "4px 9px"
    typography: "{typography.label}"
  input:
    backgroundColor: "{colors.tty-charcoal}"
    textColor: "{colors.ink}"
    typography: "{typography.body-ui}"
    rounded: "{rounded.hairline}"
    padding: "8px 10px"
  pane:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.ink}"
    rounded: "{rounded.hairline}"
    padding: "18px 16px"
  pane-title:
    textColor: "{colors.dim}"
    typography: "{typography.body-ui}"
    padding: "9px 16px"
  tmux-bar:
    backgroundColor: "{colors.shell-green}"
    textColor: "{colors.shell-green-ink}"
    typography: "{typography.body-ui}"
    height: "30px"
  tmux-window-current:
    backgroundColor: "{colors.shell-green-ink}"
    textColor: "{colors.shell-green}"
    padding: "5px 12px"
  finding-line:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.body-ui}"
    padding: "9px 16px"
  finding-line-selected:
    backgroundColor: "{colors.selection-wash}"
  tag-critical:
    textColor: "{colors.sev-red}"
    typography: "{typography.body-ui}"
  tag-high:
    textColor: "{colors.sev-magenta}"
  tag-medium:
    textColor: "{colors.sev-yellow}"
  tag-low:
    textColor: "{colors.sev-blue}"
  tag-info:
    textColor: "{colors.dim}"
  note:
    backgroundColor: "{colors.pane-raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.hairline}"
    padding: "12px 14px"
---

# Design System: breakAPI

## Overview

**Creative North Star: "The Kernel Console"**

breakAPI behaves like a well-run Linux box. The shell is a tmux session: a prompt-path breadcrumb at the top tells you where you are, a green status bar at the bottom lists the windows you can switch to. A readiness check prints like a boot checklist, a running scan streams like dmesg, and every finding reads as a man page. The world is borrowed from the terminal because its conventions already mean "calm, precise, in control", which is what a consent-first security tool needs to feel like.

It is dense but quiet. One self-hosted monospace family on a strict six-step scale, a charcoal tty ground with panes one step lighter, hairline dividers, and almost no radius. ANSI colour is rationed: each hue has a job, and nothing is coloured for decoration. Under the terminal vocabulary every control stays a standard, labeled web control; the keyboard steering (number keys, j/k, Enter, ?) is an accelerator over normal clicks, never a requirement.

The world rejects two things by name: the light stat-card security dashboard (gradient cards, big KPI tiles) and the green-matrix hacker costume (glowing text, scanlines, alarm red everywhere).

**Key Characteristics:**
- Dark tty scene on screen; light paper in print.
- One monospace family, ligatures off, tabular numbers wherever figures line up.
- Colour only does jobs: green is the shell and success, cyan is interaction, focus and selection, red/magenta/yellow/blue are severities.
- Bracketed text tags, never pills or fills.
- Hairline panes, 2px radius ceiling, flat at rest.
- Terminal anatomy (prompt path, tmux windows, boot checklist, dmesg, man page) carries the structure.

## Colors

A charcoal terminal ground with light-gray ink and a strict ANSI set, each colour assigned one job.

### Primary
- **Shell Green** (shell-green): the tmux status bar, the prompt user (`operator@breakapi`), the blinking caret, `[  OK  ]` boot marks, dmesg timestamps and 2xx statuses, completed and fixed states, primary buttons, checkbox accent, the progress bar fill. It means "the shell" and "this succeeded".
- **Shell Green Ink** (shell-green-ink): text on green, and the inverted background of the current tmux window.

### Secondary
- **Signal Cyan** (signal-cyan): everything interactive or focused. Links, breadcrumb segments, HTTP method column, request lines in evidence, the 2px focus outline, input focus border, the selected finding's left rule, running/queued states, text selection fill.
- **Selection Wash** (selection-wash): the selected finding line's background; cyan at 11% so selection reads without shouting.

### Tertiary (severities)
- **Severity Red** (sev-red): critical findings, failed/blocked states, `[ FAIL ]`, 5xx in dmesg, danger buttons, error toasts.
- **Severity Magenta** (sev-magenta): high findings only.
- **Severity Yellow** (sev-yellow): medium findings, `[ WARN ]`, paused/stopped/halted states, response status lines in evidence, 4xx in dmesg, warning notes.
- **Severity Blue** (sev-blue): low findings only.

### Neutral
- **TTY Charcoal** (tty-charcoal): the page ground, input fields and evidence `pre` blocks (inputs sit "in" the terminal, below the pane).
- **Pane** (pane): panes, the findings split, dialogs.
- **Pane Raised** (pane-raised): buttons, notes, inline code, kbd keys, toasts.
- **Hairline** (hairline): every divider and pane border.
- **Hairline Strong** (hairline-strong): control borders, scrollbar thumbs, dialog and toast borders.
- **Ink** (ink): primary text.
- **Dim** (dim): secondary text, table headers, man section labels, info severity, zero counts.

### Print
The report's print stylesheet swaps the same roles to a light palette (print-paper ground, print-ink text, darkened print-green/cyan/red/magenta/yellow/blue for contrast on white). Roles stay identical; only luminance changes.

### Named Rules
**The Colour Does Jobs Rule.** Every hue on screen must answer "what job is this doing?" with one of: shell/success (green), interaction/focus/selection (cyan), a severity (red, magenta, yellow, blue). Anything else is ink or dim.

**The No Wall Of Red Rule.** Severity colours colour text only. A list of twenty critical findings is twenty red bracketed words on charcoal, never twenty red rows or badges.

**The Dark Scene, Light Print Rule.** The app is always dark (`color-scheme: dark`); there is no light theme toggle. Paper output (`@media print` in the report) is always light.

## Typography

**Display Font:** JetBrains Mono (variable 100–800, self-hosted woff2, OFL) with ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace
**Body Font:** the same family
**Label/Mono Font:** the same family

**Character:** One monospace voice for everything, so headings, data, logs and controls all sit on the same character grid. Hierarchy comes from size and weight, not from a second family.

### Hierarchy
- **Display** (700, 28px, 1.25, -0.02em): page heads (`h1`). Drops to 22px under 640px.
- **Headline** (700, 20px, 1.25, -0.015em): the scan header identity, the man-page title (max 46ch, balanced), tally numbers.
- **Title** (700, 16px, 1.25): section `h2`, the brand wordmark (800, -0.03em).
- **Body** (400, 14px, 1.6): base text; prose capped at 72ch.
- **Body UI** (13px): the working size. Controls, labels, tables, finding lines, pane titles, man-page body, boot and compare lists.
- **Label** (700, 12px, 0.06em, uppercase): man-page section heads (NAME, SYNOPSIS, DESCRIPTION, IMPACT, FIX, EVIDENCE), table headers (600, 0.04em), dmesg, evidence `pre`, help text and meta lines at 400.

### Named Rules
**The Six Steps Rule.** Font sizes come from the scale only: 12, 13, 14, 16, 20, 28px (`--s-1`..`--s-6`). The single exception is `kbd` inside small buttons (11px).

**The Ligatures Off Rule.** `font-variant-ligatures: none` everywhere; operators like `!=` and `->` in evidence must render as typed. Figures that align (tables, dmesg, tallies, timestamps) use tabular numbers.

**The One Clock Rule.** Dates render one way in app and report: en-GB, day month year, HH:MM, zone (e.g. "29 Oct 2026, 22:41 GMT"). Elapsed log time is the dmesg form `[   12.345]`.

## Layout

The page is a terminal session in three bands: a sticky prompt line on top (brand, prompt-path breadcrumb with blinking caret, ghost actions), the content `main` (max 1280px, centred, 32px/24px padding, 96px bottom clearance for the status bar), and the tmux status bar fixed to the viewport bottom. The scan screen can go full width.

Content is grouped in panes stacked with a 20px gap; side-by-side panes auto-fit at a 300px minimum with a 24px gutter. The scan screen is a tmux split: a findings list (320–420px, sticky under the prompt, scrolls internally) beside the man page. Inside a man page, sections are a two-column grid (14ch label column, body capped at 72ch). Boot, compare and finding lines use fixed `ch` columns so tags and states align like terminal output.

Spacing works on a 4/8 rhythm: 4, 8, 16, 24, 32px, with 20px between panes and 18px inside pane bodies and between fields.

Responsive: under 1100px the scan header's actions wrap to their own row; under 900px the split stacks (list above, capped at 360px) and man sections collapse to one column; under 640px the breadcrumb collapses to `…/here`, the tmux bar drops its session and clock and wraps its windows onto multiple lines while staying fixed at the bottom, and padding tightens to 16px.

### Named Rules
**The Fixed Status Bar Rule.** The tmux bar is always fixed at the viewport bottom, on every screen inside a project and at every width. On mobile it wraps; it never scrolls away or moves to the top. Content keeps enough bottom padding to clear it.

## Elevation & Depth

Flat. Depth is tonal: charcoal ground, panes one step lighter, raised controls one more step, inputs and code back down to the ground. Hairline borders do the separating. Shadows appear only on the two things that float over the page.

### Shadow Vocabulary
- **Toast float** (`box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45)`): the bottom-centre status toast.
- **Dialog float** (`box-shadow: 0 16px 48px rgba(0, 0, 0, 0.55)`, backdrop `rgba(5, 6, 7, 0.65)`): the key map and other modal dialogs.
- **Key cap** (`box-shadow: inset 0 -1px 0` hairline-strong): `kbd` keys only.

### Named Rules
**The Flat Panes Rule.** Panes, cards, lists and controls carry no shadow. If something needs to stand out at rest, it gets a hairline or a tone step, not a glow.

## Shapes

Square terminal geometry. Every pane, button, input, note, `pre`, dialog and toast uses a 2px corner, which reads as square but avoids aliasing. Borders are 1px hairlines; the selected finding gets a 1px cyan left rule; focus is a 2px cyan outline offset 2px. The progress bar is a segmented block meter (6px blocks, 2px gaps) rather than a smooth fill.

### Named Rules
**The Two Pixel Ceiling Rule.** No radius above 2px on any surface. No rounded cards, no pills, no circles.

## Components

### Buttons
Standard labeled buttons, compact and square, with an optional `kbd` hint for their key.
- **Shape:** square-edged (2px), 1px border, 600 weight at 13px, 8px icon/kbd gap.
- **Default:** pane-raised fill, hairline-strong border, ink text; hover lifts the border to dim and the fill one tone (#262a2f).
- **Primary:** shell-green fill and border, green-ink text; hover brightens (#6ae99e). At most one or two per view (Start, Retest).
- **Danger:** transparent, red text and 45% red border; hover adds a 10% red wash. Stop and revoke.
- **Ghost:** transparent and borderless, dim text; hover shows ink text and a hairline border. Used in the prompt line and dialog close.
- **Small:** 4px 9px padding at 12px.
- **States:** disabled at 45% opacity with not-allowed cursor; busy (`aria-busy`) at 70% with progress cursor. Colour transitions 120ms, removed under reduced motion.

### Chips (severity and state tags)
- **Style:** bracketed uppercase text in a fixed 6ch column, 700 weight, no background, border or radius: `[CRIT]` red, `[HIGH]` magenta, `[MED ]` yellow, `[LOW ]` blue, `[INFO]` dim at 500. Short labels are space-padded to four characters so the brackets align down a list.
- **State words:** scan states are bold coloured words (completed green; running/queued cyan; paused/stopped/halted/interrupted yellow; failed/blocked red).

### Cards / Containers (panes)
- **Corner Style:** 2px.
- **Background:** pane on the charcoal ground.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px hairline; a pane title bar (9px 16px, 13px dim text with an ink `h2`, actions pushed right) separated by a hairline.
- **Internal Padding:** 18px 16px.
- **Notes:** pane-raised boxes with a hairline-strong border tinted by meaning (45% yellow warn, 45% red bad, 45% green ok), leading with a bold label.

### Inputs / Fields
- **Style:** full-width, charcoal ground (one step below the pane), hairline-strong border, 2px radius, 8px 10px padding, 13px. Label above in 600 weight with an optional dim hint; dim help text below at 12px. Placeholder #7f868e.
- **Focus:** border turns cyan plus a 1px cyan ring; no glow.
- **Checkboxes / radios:** native, green accent, 15px, in a flex row with their full-sentence label.
- **Command row:** a green `$`-style prompt label beside a flexible input, for single-value entry like base URLs.

### Navigation
- **Prompt path:** `operator@breakapi:~/project/section$` with a blinking green block caret. User in green, separators dim, ancestors as cyan links, current segment ink. Collapses to `…/here` on mobile.
- **tmux status bar:** green bar, `[breakapi]` session name in 800, windows `0:authorization` through `4:scans`. The current window inverts (green-ink background, green text, 700) and carries a `*` flag; a window needing attention carries `!` (with a "Needs attention" title). Scan state and the clock sit at the right.
- **Keyboard:** number keys 0–4 switch windows, j/k or arrows move findings, Enter opens, u goes up, ? opens the key map dialog. Keys never fire inside form fields.

### Boot checklist
Readiness printed as boot lines: a 9ch status column `[  OK  ]` green, `[ WARN ]` yellow, `[ FAIL ]` red, then the item as a link to where it is fixed.

### dmesg log
Live request log at 12px/1.7, tabular figures, one ellipsised line per request: green elapsed timestamp `[   12.345]`, status coloured by class (2xx green, 4xx yellow, 5xx red), method and URL in ink, account and purpose dim.

### Findings list and man page
The scan split. Each finding line is a two-column grid (7ch tag, then title in 600 with a dim endpoint line below); the selected line gets the cyan wash and left rule and is a listbox option. The man page opens with a dim header `BREAKAPI-CHECK(7) · breakAPI findings · BREAKAPI-CHECK(7)`, a 20px title, then labelled sections NAME, SYNOPSIS, DESCRIPTION, IMPACT, FIX, EVIDENCE, and a dim footer with scan id and date. Evidence is a charcoal `pre` with the request line in cyan and the HTTP status in yellow.

### Report (Read mode)
The printable report is the same man-page anatomy at page scale (max 980px): header and footer rules, 15ch section labels, findings separated by hairlines, the authorization record included. In print it switches to the light palette, expands all collapsed evidence and keeps each finding unbroken.

## Do's and Don'ts

### Do:
- **Do** take every font size from the 12/13/14/16/20/28px scale.
- **Do** give every colour a job: green for shell and success, cyan for interaction, focus and selection, the four ANSI severities for severity.
- **Do** render severity as bracketed text tags (`[CRIT]`, `[HIGH]`, `[MED ]`, `[LOW ]`, `[INFO]`), padded so the brackets align.
- **Do** keep the tmux status bar fixed at the viewport bottom and let it wrap on mobile.
- **Do** format dates one way everywhere: en-GB, day month year, HH:MM, zone.
- **Do** use standard labeled web controls (button, input, select, checkbox, dialog) under the terminal vocabulary, and keep every keyboard shortcut optional.
- **Do** keep styling CSP-safe: no inline `style` attributes or inline scripts; set dynamic values through the CSSOM (`el.style.width`, `setProperty`).
- **Do** keep the app dark and the printed report light.

### Don't:
- **Don't** put severity on fills, pills, badges or coloured rows; lists must never become a wall of red.
- **Don't** use a radius above 2px, rounded cards, or pill shapes.
- **Don't** add shadows to panes, buttons or lists; only the toast and dialogs float.
- **Don't** build the light stat-card security dashboard (KPI tiles, gradient cards).
- **Don't** dress it as a hacker movie: no glowing text, scanlines, CRT effects or matrix green on everything.
- **Don't** introduce a second typeface or turn ligatures on.
- **Don't** replace a real control with a fake terminal input that only accepts typed commands.

## Demo disclaimer

Every page, including reports, ends with a fixed, centred strip reading "This is a testing demo application only." It sits below the tmux bar, which is offset by `--disclaimer-h`, and uses `--pane-2` with `--ink` text so it stays readable without competing with severity colours.
