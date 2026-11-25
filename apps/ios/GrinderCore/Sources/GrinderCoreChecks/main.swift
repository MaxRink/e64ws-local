import Foundation
import GrinderCoreChecksKit

/// Portable test harness.
///
/// Runs every case in `allChecks()` with no XCTest dependency, so the package is
/// verifiable on a host that only has the Command Line Tools:
///
///     swift run GrinderCoreChecks
///
/// Exit status 0 means every case passed.  On a host with Xcode, `swift test`
/// runs the identical cases through XCTest.
@main
struct GrinderCoreChecksMain {
    static func main() async {
        let cases = allChecks()
        var failures: [(name: String, error: String)] = []

        for checkCase in cases {
            do {
                try await checkCase.body()
                print("ok   \(checkCase.name)")
            } catch {
                failures.append((checkCase.name, String(describing: error)))
                print("FAIL \(checkCase.name)")
            }
        }

        if failures.isEmpty {
            print("\n\(cases.count) checks passed")
            exit(0)
        }

        print("\n\(failures.count) of \(cases.count) checks failed:")
        for failure in failures {
            print("  - \(failure.name)\n    \(failure.error)")
        }
        exit(1)
    }
}
