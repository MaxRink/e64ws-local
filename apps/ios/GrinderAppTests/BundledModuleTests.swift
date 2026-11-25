import XCTest
import GrinderCore

/// The app target's checks, run in Xcode against the built app bundle.
///
/// The core logic is covered by GrinderCoreTests (the same cases the portable
/// `swift run GrinderCoreChecks` harness runs).  These assert the two things
/// that only exist once the app is assembled: the bundled PHP module is the
/// pinned one, and the Info.plist keeps the promised ATS shape.
final class BundledModuleTests: XCTestCase {
    func testBundledModuleMatchesPinnedDigest() throws {
        let module = try BundledModule.load()
        XCTAssertEqual(Fingerprints.sha256Hex(module.data), BundledModule.expectedSHA256)
    }

    func testInfoPlistAllowsLocalNetworkingOnly() throws {
        let aps = try XCTUnwrap(
            Bundle.main.object(forInfoDictionaryKey: "NSAppTransportSecurity") as? [String: Any]
        )
        XCTAssertEqual(aps["NSAllowsLocalNetworking"] as? Bool, true)
        // No blanket exception: nothing may disable TLS or allow arbitrary loads.
        XCTAssertNil(aps["NSAllowsArbitraryLoads"])
        XCTAssertNil(aps["NSExceptionDomains"])
    }

    func testLocalNetworkUsageDescriptionIsPresent() throws {
        let description = try XCTUnwrap(
            Bundle.main.object(forInfoDictionaryKey: "NSLocalNetworkUsageDescription") as? String
        )
        XCTAssertFalse(description.isEmpty)
    }
}
