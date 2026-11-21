#!/usr/bin/env bash
# Selects the newest *released* Xcode installed on the build Mac (betas and release candidates are
# skipped: App Store Connect rejects apps built with them). Apple requires the iOS 27 SDK from
# April 2027, so the default (older) Xcode is not good enough.
set -euo pipefail

echo "installed:"; ls -d /Applications/Xcode*.app | sed 's/^/  /'
best=""
best_ver=""
for app in /Applications/Xcode_*.app; do
  [ -d "$app" ] || continue
  name=$(basename "$app" .app)
  case "$name" in *beta*|*Beta*|*RC*|*_rc*|*Release_Candidate*) continue ;; esac
  ver=${name#Xcode_}
  [[ "$ver" =~ ^[0-9]+(\.[0-9]+)*$ ]] || continue
  if [ -z "$best_ver" ] || [ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -1)" = "$ver" ]; then
    best="$app"
    best_ver="$ver"
  fi
done

if [ -z "$best" ]; then
  echo "no released Xcode found; keeping the default" >&2
else
  echo "selecting $best"
  sudo xcode-select -s "$best/Contents/Developer"
fi
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-version | sed 's/^/iOS SDK /'
