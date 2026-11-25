#!/bin/sh
# Build a self-contained .app bundle with the command-line Swift toolchain.
set -eu
cd "$(dirname "$0")"
CONFIG="${CONFIG:-release}"
swift build -c "$CONFIG"
BIN=".build/$CONFIG/VirtualGrinderApp"
APP="dist/VirtualGrinder.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/VirtualGrinderApp"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>VirtualGrinderApp</string>
  <key>CFBundleIdentifier</key><string>de.mahlkoenig.research.virtualgrinder</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Virtual Grinder</string>
  <key>CFBundleDisplayName</key><string>Mahlkönig Virtual Grinder</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
echo "$APP"
