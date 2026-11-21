#!/usr/bin/env bash
# Builds the Rust core for iPhone (device + Apple-silicon simulator) and packages it as an XCFramework.
set -euo pipefail
cd "$(dirname "$0")/.."
export IPHONEOS_DEPLOYMENT_TARGET=17.0

(cd core && cargo build --locked --release --target aarch64-apple-ios)
(cd core && cargo build --locked --release --target aarch64-apple-ios-sim)

rm -rf build/ScytaleCore.xcframework
mkdir -p build
xcodebuild -create-xcframework \
  -library core/target/aarch64-apple-ios/release/libscytale_core.a -headers core/include \
  -library core/target/aarch64-apple-ios-sim/release/libscytale_core.a -headers core/include \
  -output build/ScytaleCore.xcframework
