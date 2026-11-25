#!/bin/sh
# Verify the SwiftUI app sources on a host without Xcode or the iOS SDK.
#
# Two checks, both runnable with the Command Line Tools only:
#
#   1. Syntax check of every app source (GrinderApp.swift, AppModel.swift,
#      Screens/*.swift) with `swiftc -parse`.  This proves the SwiftUI target is
#      syntactically valid.
#
#   2. Full type check of AppModel.swift — the app's non-view logic — against
#      the GrinderCore module and the macOS SDK.  This is where the app wires the
#      device, the token, the session and the setup protocol together, so it is
#      the part that can be checked without SwiftUI's macro plugin.
#
# The views themselves are type-checked by Xcode when the project is built from
# project.yml: SwiftUI's @State / @EnvironmentObject are macros implemented by
# SwiftUIMacros, which ships only inside Xcode, so a type check of the views is
# not possible with the Command Line Tools alone.  See apps/ios/README.md.
#
#   sh scripts/verify-app-sources.sh

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
core="$here/GrinderCore"
app="$here/GrinderApp"
sdk=$(xcrun --sdk macosx --show-sdk-path)

echo "== building GrinderCore for macOS =="
(cd "$core" && swift build --product GrinderCore)

module_dir=$(dirname "$(find "$core/.build" -name 'GrinderCore.swiftmodule' -type f 2>/dev/null | head -n 1)")
if [ -z "$module_dir" ] || [ ! -d "$module_dir" ]; then
  echo "verify: cannot find the GrinderCore module under $core/.build" >&2
  exit 1
fi

echo "== syntax check: every SwiftUI source =="
for source in "$app/GrinderApp.swift" "$app/AppModel.swift" "$app/Screens/"*.swift; do
  printf -- '-- %s\n' "$(basename "$source")"
  swiftc -parse -swift-version 5 "$source"
done

echo "== type check: AppModel (app logic) =="
swiftc -typecheck \
  -sdk "$sdk" \
  -target arm64-apple-macos14.0 \
  -I "$module_dir" \
  -swift-version 5 \
  "$app/AppModel.swift"

echo "verify: app sources parse, AppModel type-checks"
