#!/usr/bin/env bash
# Installs a pinned XcodeGen release and verifies it against its published SHA-256 before use.
# (Previously `brew install xcodegen`, which took whatever version was newest.)
set -euo pipefail

VERSION=2.46.0
SHA256=4d9e34b62172d645eed6457cac13fc222569974098ef4ee9c3368bedf0196806

dest="${RUNNER_TEMP:-/tmp}/xcodegen-$VERSION"
zip="$dest.zip"
curl -fsSL --retry 3 -o "$zip" "https://github.com/yonaskolb/XcodeGen/releases/download/$VERSION/xcodegen.zip"
echo "$SHA256  $zip" | shasum -a 256 -c -
rm -rf "$dest"
mkdir -p "$dest"
unzip -q "$zip" -d "$dest"
bin=$(find "$dest" -type f -name xcodegen -perm -u+x | head -1)
[ -n "$bin" ] || { echo "xcodegen binary not found in archive" >&2; exit 1; }
dir=$(dirname "$bin")
echo "$dir" >> "$GITHUB_PATH"
"$bin" --version
