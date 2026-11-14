#!/bin/sh
# Stop hook: block once if non-doc files changed but docs/STATUS.md did not (see CLAUDE.md "Done means").
in=$(cat)
case "$in" in *'"stop_hook_active":true'*|*'"stop_hook_active": true'*) exit 0;; esac
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
changed=$(git status --porcelain -uall 2>/dev/null | cut -c4-)
[ -z "$changed" ] && exit 0
echo "$changed" | grep -q '^docs/STATUS\.md$' && exit 0
# shortcut: any non-markdown file outside docs/, .claude/, .impeccable/ counts as code/config; refine if it nags.
code=$(echo "$changed" | grep -Ev '^(docs/|\.claude/|\.impeccable/)|\.md$')
[ -z "$code" ] && exit 0
printf '%s\n' '{"decision":"block","reason":"Code or config changed but docs/STATUS.md did not. Follow the CLAUDE.md \"Done means\" checklist: update docs/STATUS.md and every doc your change touches, then finish."}'
