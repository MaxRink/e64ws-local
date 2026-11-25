#!/bin/sh
# Everything that can be verified on this host, in one command:
#
#   1. GrinderCore: build every target (including the XCTest target) and run
#      all checks through the portable harness.  `swift test` runs the same
#      cases as XCTest on a host with Xcode.
#   2. App sources: syntax check of every view, full type check of AppModel.
#
#   sh scripts/verify.sh
#
# The iOS app itself needs Xcode (project.yml + XcodeGen); see README.md.

set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "############ GrinderCore: build all targets ############"
(cd "$here/GrinderCore" && swift build --build-tests)

echo
echo "############ GrinderCore: checks ############"
(cd "$here/GrinderCore" && swift run GrinderCoreChecks)

echo
echo "############ App sources ############"
sh "$here/scripts/verify-app-sources.sh"
