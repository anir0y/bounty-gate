#!/usr/bin/env bash
# upstream_watch.sh — launchd wrapper for tools/upstream_watch.py (com.seethaai.upstreamwatch).
# Silent unless a watched repo shipped something new, or a repo went unreachable.
# Read-only against GitHub. Never writes to skills/ tools/ commands/ — leads only.
set -uo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# REPO from this script's own location — never hardcode (the 2026-07-18 move to
# seethaai/ left 7 launchd agents dead at exit 127 for two weeks on hardcoded paths).
REPO="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
STATE="$REPO/.cache/upstream_watch"
LOG="$STATE/wrapper.log"
IMSG="${UPSTREAM_WATCH_IMESSAGE:-}"   # unset = log only, no notification
mkdir -p "$STATE"
TS="$(date '+%Y-%m-%d %H:%M')"

imsg() { [ -n "$IMSG" ] || return 0; osascript -e "tell application \"Messages\" to send \"$1\" to buddy \"$IMSG\" of (1st service whose service type = iMessage)" 2>/dev/null || true; }

cd "$REPO" || { echo "[$TS] FATAL cannot cd $REPO" >> "$LOG"; exit 1; }

OUT="$(python3 tools/upstream_watch.py --check --quiet 2>&1)"; RC=$?

# exit 3 = the watch table parsed to zero repos. That is a broken parser, and it
# MUST shout: a silently-empty watch list is a fail-open that reads as "all quiet".
if [ "$RC" = "3" ]; then
  echo "[$TS] FATAL parser returned 0 repos" >> "$LOG"
  imsg "SeethaAi upstream_watch BROKEN: watch table parsed 0 repos — nothing is being watched."
  exit 3
fi

[ -z "$OUT" ] && { echo "[$TS] quiet" >> "$LOG"; exit 0; }

echo "[$TS] ---- signals ----" >> "$LOG"
echo "$OUT" >> "$LOG"

NEW="$(printf '%s' "$OUT" | sed -n 's/^new leads *: *\([0-9]*\).*/\1/p' | head -1)"
GAPS="$(printf '%s' "$OUT" | sed -n 's/.*\*\*\([0-9]*\) match no component.*/\1/p' | head -1)"
ERRS="$(printf '%s' "$OUT" | grep -c '^  ! ' || true)"

if [ "${NEW:-0}" != "0" ] || [ "${ERRS:-0}" != "0" ]; then
  imsg "SeethaAi upstream: ${NEW:-0} new signals (${GAPS:-0} unmatched), ${ERRS:-0} unreachable. Review: upstream_watch.py --digest --gaps-only"
fi
exit 0
