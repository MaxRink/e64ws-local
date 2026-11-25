import Foundation
import GrinderCore

/// `swift run GrinderCoreE2E` — the end-to-end suite for the Local Owner API.
///
/// The contract, exactly:
///
/// | situation | output | exit |
/// |---|---|---|
/// | `E64_E2E_BASE_URL` unset or empty | `E2E SKIP (no E64_E2E_BASE_URL)` | 0 |
/// | every check passed | `E2E PASS <n>` | 0 |
/// | one check failed | `E2E FAIL <detail>` on stderr | 1 |
///
/// stdout carries the summary line and nothing else; `E64_E2E_VERBOSE=1` adds one
/// line per check on stderr, and every failure detail goes through the secret
/// scrubber before it is written.
@main
struct GrinderCoreE2EMain {
    static func main() async {
        let environment = ProcessInfo.processInfo.environment

        let config: E2EConfig
        do {
            guard let loaded = try E2EConfig.load(from: environment) else {
                print("E2E SKIP (no \(E2EConfig.baseURLKey))")
                exit(0)
            }
            config = loaded
        } catch {
            // The token may never have been parsed, so register it from the raw
            // environment before the failure line is written.
            let early = SecretRegistry()
            early.add(environment[E2EConfig.tokenKey])
            report(error, secrets: early)
            exit(1)
        }

        let secrets = SecretRegistry()
        secrets.add(config.token)
        let checks = Checks(verbose: config.verbose, secrets: secrets)

        do {
            let harness = try Harness(config: config, checks: checks, secrets: secrets)
            try await harness.run()
            print("E2E PASS \(checks.count)")
            exit(0)
        } catch {
            report(error, secrets: secrets)
            exit(1)
        }
    }

    /// `E2E FAIL <detail>` on stderr, with every registered secret replaced.
    ///
    /// Only the registered secrets (the token, each session id) are hidden, not
    /// every secret-shaped string: the shipped redactor's patterns also match an
    /// address or the word "session:" followed by a value, and a failure line that
    /// cannot name the host it failed to reach is not a useful failure line.
    private static func report(_ error: Error, secrets: SecretRegistry) {
        let detail = (error as? E2EFailure)?.detail ?? describe(error)
        FileHandle.standardError.write(Data(("E2E FAIL " + secrets.hide(detail) + "\n").utf8))
    }

    private static func describe(_ error: Error) -> String {
        if let localized = (error as? LocalizedError)?.errorDescription, !localized.isEmpty {
            return localized
        }
        return String(describing: error)
    }
}
