// swift-tools-version:5.10
//
// GrinderCore — the testable half of the E64 local iOS app.
//
// No third-party dependencies.  The package builds and runs its checks on any
// macOS host with the Swift toolchain, including one that only has the Command
// Line Tools (no Xcode): `swift run GrinderCoreChecks`.  On a host with Xcode,
// `swift test` runs the XCTest target in Tests/GrinderCoreTests, which executes
// the same cases from GrinderCoreChecksKit.
//
// GrinderCoreE2E is the one target that needs a peer: it drives the real
// LocalAPI and ActionClient over URLSession against tools/e64ws_simulator.py.
// It skips itself when E64_E2E_BASE_URL is absent, so an offline host still
// builds it and sees no failure.
//
// The SwiftUI application itself lives in ../GrinderApp and is generated from
// ../project.yml with XcodeGen; it is not part of this package.

import PackageDescription

let package = Package(
    name: "GrinderCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "GrinderCore", targets: ["GrinderCore"]),
        .executable(name: "GrinderCoreChecks", targets: ["GrinderCoreChecks"]),
        .executable(name: "GrinderCoreE2E", targets: ["GrinderCoreE2E"]),
    ],
    targets: [
        .target(
            name: "GrinderCore",
            resources: [
                // Byte-identical copies of ondevice/rest_api_dev.php and
                // ondevice/e64local_action_run.php.  Checks pin both SHA-256s
                // and compare them with the repository copies.
                .copy("Resources/rest_api_dev.php"),
                .copy("Resources/e64local_action_run.php"),
            ]
        ),
        .target(
            name: "GrinderCoreChecksKit",
            dependencies: ["GrinderCore"]
        ),
        // Portable harness: runs the cases without XCTest, so verification
        // works on a Command-Line-Tools-only host.
        .executableTarget(
            name: "GrinderCoreChecks",
            dependencies: ["GrinderCoreChecksKit"]
        ),
        // End-to-end harness: the real clients over a real URLSession against
        // tools/e64ws_simulator.py.  It owns its own transport because the
        // production one is pinned to https and to the device's certificate.
        .executableTarget(
            name: "GrinderCoreE2E",
            dependencies: ["GrinderCore"]
        ),
        .testTarget(
            name: "GrinderCoreTests",
            dependencies: ["GrinderCore", "GrinderCoreChecksKit"]
        ),
    ]
)
