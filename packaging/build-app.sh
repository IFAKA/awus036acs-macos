#!/bin/sh
# Build build/AWUS WiFi.app from app/*.swift with swiftc only (no Xcode project). Ad-hoc signed.
set -eu
cd "$(dirname "$0")/.."
APP="build/AWUS WiFi.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -target arm64-apple-macos13.0 -o "$APP/Contents/MacOS/AWUS WiFi" app/*.swift -framework Cocoa
cp packaging/Info.plist "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
codesign --force --sign - "$APP"
codesign --verify --strict "$APP"
echo "built $APP"
