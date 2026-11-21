#!/usr/bin/env bash
# Watchdog: searches GitHub for Scytale's provenance marker outside Forenthal's own repositories.
# Any hit is a possible copy of the code. It is reported for review; nothing is done automatically.
# Exit 0 = nothing found, 1 = possible copies found (listed), 2 = the search itself failed.
set -uo pipefail

MARKER=$(grep -o 'scytale-provenance-[0-9a-f]\{32\}' "$(dirname "$0")/../core/src/lib.rs" | head -1)
OWNER="${OWNER:-Forenthal}"
[ -n "$MARKER" ] || { echo "marker not found in core/src/lib.rs" >&2; exit 2; }

if ! out=$(gh api -X GET search/code -f q="\"$MARKER\"" -f per_page=100 \
      --jq '.items[] | "\(.repository.full_name)\t\(.path)\t\(.html_url)"' 2>&1); then
  echo "search failed: $out" >&2
  exit 2
fi

hits=$(printf '%s\n' "$out" | grep -v '^$' | awk -F'\t' -v o="$OWNER" 'tolower(substr($1, 1, length(o) + 1)) != tolower(o "/")')

if [ -z "$hits" ]; then
  echo "No copies found outside $OWNER's repositories."
  exit 0
fi

echo "POSSIBLE COPIES OF SCYTALE (marker found outside $OWNER):"
printf '%s\n' "$hits" | awk -F'\t' '{printf "  %s  %s\n    %s\n", $1, $2, $3}'
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Possible copies of Scytale"
    echo "The provenance marker was found outside $OWNER's repositories. Review before acting."
    echo
    printf '%s\n' "$hits" | awk -F'\t' '{printf "- [%s](%s) `%s`\n", $1, $3, $2}'
  } >> "$GITHUB_STEP_SUMMARY"
fi
exit 1
