import Foundation
import GrinderCore

/// The harness contract, in one place.
///
/// - `E64_E2E_BASE_URL` — plain `http://host:port`, no trailing slash.  Unset (or
///   empty) means "skip": the suite prints one line and runs nothing.
/// - `E64_E2E_TOKEN` — the owner token the fixture accepts.
/// - `E64_E2E_VERBOSE` — optional.  `1`/`true`/`yes` prints one line per check
///   to stderr.  stdout stays exactly the summary line either way.
struct E2EConfig: Sendable {
    static let baseURLKey = "E64_E2E_BASE_URL"
    static let tokenKey = "E64_E2E_TOKEN"
    static let verboseKey = "E64_E2E_VERBOSE"

    let baseURL: URL
    let scheme: String
    let host: String
    let port: Int
    let token: String
    let verbose: Bool

    /// `nil` means "no base URL, so skip".
    static func load(from environment: [String: String]) throws -> E2EConfig? {
        guard let raw = environment[baseURLKey]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty
        else { return nil }

        var text = raw
        while text.hasSuffix("/") { text.removeLast() }
        guard let url = URL(string: text),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = url.host,
              !host.isEmpty
        else {
            // The value itself is not echoed: a malformed variable could still
            // contain a credential, and the variable name is enough to fix it.
            throw E2EFailure("\(baseURLKey) is not a plain http(s) URL")
        }
        guard url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/" else {
            throw E2EFailure("\(baseURLKey) must be a base URL without a path, query or fragment")
        }
        guard url.user == nil, url.password == nil else {
            throw E2EFailure("\(baseURLKey) must not carry user info")
        }
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        guard (1...65535).contains(port) else {
            throw E2EFailure("\(baseURLKey) has a port outside 1–65535")
        }
        guard let token = environment[tokenKey]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty
        else {
            throw E2EFailure("\(tokenKey) is not set, so no owner token can be sent")
        }
        let verbose = ["1", "true", "yes"].contains(
            environment[verboseKey]?.lowercased() ?? ""
        )
        return E2EConfig(
            baseURL: url,
            scheme: scheme,
            host: host,
            port: port,
            token: token,
            verbose: verbose
        )
    }

    /// `host:port`, for messages.  Never carries a credential.
    var authority: String { port == 80 || port == 443 ? host : "\(host):\(port)" }
}

/// One failed check.  The detail is printed after the secret scrubber has run
/// over it, so a failure line cannot leak the token or a session id.
struct E2EFailure: Error, CustomStringConvertible {
    let detail: String

    init(_ detail: String) { self.detail = detail }

    var description: String { detail }
}

/// Every value that must never appear in output.  The suite registers the
/// fixture token and each session it opens; the failure path and the verbose
/// path both run through it.
final class SecretRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []

    func add(_ secret: String?) {
        guard let secret, !secret.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        if !values.contains(secret) { values.append(secret) }
    }

    func all() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }

    /// Replace every registered secret with a marker.
    ///
    /// Deliberately not the shipped `LogRedaction`: its patterns also match a bare
    /// address and the phrase "session: check_session", so running it over the
    /// harness's own lines would hide the host that failed to answer and mangle
    /// the check names.  The shipped redactor is asserted separately, on a
    /// secret-shaped line, in `TokenSuite`.
    func hide(_ text: String) -> String {
        var output = text
        for secret in all() { output = output.replacingOccurrences(of: secret, with: "<redacted>") }
        return output
    }
}

/// The assertion counter.
///
/// One `expect*` call is one check.  The first failure throws, so the suite
/// reports the check that broke rather than a cascade.
final class Checks: @unchecked Sendable {
    private(set) var count = 0
    private let verbose: Bool
    private let secrets: SecretRegistry

    init(verbose: Bool, secrets: SecretRegistry) {
        self.verbose = verbose
        self.secrets = secrets
    }

    func expect(_ condition: Bool, _ description: @autoclosure () -> String) throws {
        count += 1
        let detail = description()
        guard condition else { throw E2EFailure(detail) }
        if verbose {
            write("ok   \(count) \(secrets.hide(detail))\n")
        }
    }

    func expectEqual<T: Equatable>(
        _ actual: T,
        _ expected: T,
        _ description: @autoclosure () -> String
    ) throws {
        try expect(
            actual == expected,
            "\(description()) (expected \(expected), got \(actual))"
        )
    }

    private func write(_ text: String) {
        FileHandle.standardError.write(Data(text.utf8))
    }
}
