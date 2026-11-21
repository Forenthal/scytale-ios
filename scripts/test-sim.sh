#!/usr/bin/env bash
# Runs the unit tests on the newest available iPhone simulator.
set -euo pipefail
cd "$(dirname "$0")/../ios"

UDID=$(xcrun simctl list devices available -j | python3 -I -c '
import json, re, sys
devs = json.load(sys.stdin)["devices"]
def ver(rt):
    m = re.search(r"iOS-(\d+)-(\d+)", rt)
    return (int(m.group(1)), int(m.group(2))) if m else (-1, -1)
for rt in sorted(devs, key=ver, reverse=True):
    if ver(rt)[0] < 0:
        continue
    phones = [d for d in devs[rt] if d["name"].startswith("iPhone")]
    if phones:
        print(phones[0]["udid"]); break
')
if [ -z "$UDID" ]; then echo "no iPhone simulator available" >&2; exit 1; fi
echo "simulator: $UDID"

# The preview Xcode 27 simulators occasionally fail to launch the test host ("Lost pending
# connection to the test runner"). Retry once, loudly; a real failure fails both attempts.
for attempt in 1 2; do
  if xcodebuild test \
      -project Scytale.xcodeproj \
      -scheme Scytale \
      -destination "id=$UDID" \
      CODE_SIGN_STYLE=Manual \
      CODE_SIGN_IDENTITY=- \
      DEVELOPMENT_TEAM=; then
    exit 0
  fi
  echo "::warning::simulator test attempt $attempt failed"
  xcrun simctl shutdown "$UDID" >/dev/null 2>&1 || true
done
exit 1
