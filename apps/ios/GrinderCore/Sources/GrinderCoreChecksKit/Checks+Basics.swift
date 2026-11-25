import Foundation
import GrinderCore

/// Minimal assertion helpers and a registry, shared by the XCTest target and
/// the portable check runner.
///
/// XCTest is not part of the Command Line Tools toolchain, so the same cases
/// are written once as throwing functions here and executed by whichever
/// harness the host has.  `swift test` on a machine with Xcode, or
/// `swift run GrinderCoreChecks` anywhere with a Swift toolchain.
public struct CheckFailure: Error, CustomStringConvertible {
    public let message: String
    public let file: StaticString
    public let line: UInt

    public var description: String { "\(file):\(line): \(message)" }
}

public func check(
    _ condition: Bool,
    _ message: @autoclosure () -> String,
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    guard condition else {
        throw CheckFailure(message: message(), file: file, line: line)
    }
}

public func checkEqual<T: Equatable>(
    _ actual: T,
    _ expected: T,
    _ label: String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    guard actual == expected else {
        throw CheckFailure(
            message: "\(label.isEmpty ? "" : label + ": ")expected \(expected), got \(actual)",
            file: file,
            line: line
        )
    }
}

public func checkNil<T>(_ value: T?, _ label: String = "", file: StaticString = #filePath, line: UInt = #line) throws {
    guard value == nil else {
        throw CheckFailure(message: "\(label) expected nil, got \(String(describing: value))", file: file, line: line)
    }
}


@discardableResult
public func checkNotNil<T>(_ value: T?, _ label: String = "", file: StaticString = #filePath, line: UInt = #line) throws -> T {
    guard let value else {
        throw CheckFailure(message: "\(label) expected a value, got nil", file: file, line: line)
    }
    return value
}

/// A named case: what the XCTest target turns into a method and the runner runs.
public struct CheckCase: Sendable {
    public let name: String
    public let body: @Sendable () async throws -> Void

    public init(_ name: String, _ body: @escaping @Sendable () async throws -> Void) {
        self.name = name
        self.body = body
    }
}

/// All cases, in the order they are reported.
public func allChecks() -> [CheckCase] {
    let base = endpointChecks()
        + formChecks()
        + isolationChecks()
        + trustChecks()
        + tokenChecks()
        + apiChecks()
        + logQueryChecks()
        + fileAllowlistChecks()
        + moduleChecks()
        + setupChecks()
        + proberChecks()
        + actionChecks()
        + actionSourceChecks()
        + redactionChecks()
        + sourceChecks()
    // The generated XCTest target must list exactly these cases, including the
    // one that verifies it.  Passing the names in keeps the check from calling
    // allChecks() again (which would recurse).
    return base + generatedCasesCheck(others: base.map(\.name))
}

// MARK: - Endpoint

func endpointChecks() -> [CheckCase] {
    [
        CheckCase("endpoint: bare host uses the default port") {
            let endpoint = try Endpoint(host: "192.168.1.100")
            try checkEqual(endpoint.host, "192.168.1.100")
            try checkEqual(endpoint.port, 443)
            try checkEqual(endpoint.baseURL.absoluteString, "https://192.168.1.100")
        },
        CheckCase("endpoint: host:port is parsed") {
            let endpoint = try Endpoint(hostAndPort: "grinder.local:8443")
            try checkEqual(endpoint.host, "grinder.local")
            try checkEqual(endpoint.port, 8443)
            try checkEqual(endpoint.authority, "grinder.local:8443")
        },
        CheckCase("endpoint: bracketed IPv6 with a port") {
            let endpoint = try Endpoint(hostAndPort: "[fe80::1]:443")
            try checkEqual(endpoint.host, "fe80::1")
            try checkEqual(endpoint.authority, "[fe80::1]")
        },
        CheckCase("endpoint: a URL is rejected, not silently parsed") {
            var threw = false
            do { _ = try Endpoint(hostAndPort: "https://192.168.1.100/rest_api") } catch { threw = true }
            try check(threw, "a URL must be rejected")
        },
        CheckCase("endpoint: a path is rejected") {
            var threw = false
            do { _ = try Endpoint(hostAndPort: "192.168.1.100/rest_api") } catch { threw = true }
            try check(threw, "a path must be rejected")
        },
        CheckCase("endpoint: an out-of-range port is rejected") {
            var threw = false
            do { _ = try Endpoint(host: "192.168.1.100", port: 70000) } catch { threw = true }
            try check(threw, "port 70000 must be rejected")
        },
    ]
}

// MARK: - Form encoding

func formChecks() -> [CheckCase] {
    [
        CheckCase("form: login fields keep the e64root order") {
            let body = String(data: VendorLogin.body(password: "s3cret"), encoding: .utf8)
            try checkEqual(body, "login=1&requestDeveloper=1&password=s3cret&userRole=Owner")
        },
        CheckCase("form: the injection payload is fully percent-encoded") {
            let role = try LoginInjection.userRole(command: "id; ls")
            try checkEqual(role, "x';id; ls;#")
            let encoded = FormEncoding.percentEncode(role)
            try check(!encoded.contains("'"), "a quote must be encoded")
            try check(!encoded.contains(";"), "a semicolon must be encoded")
            try check(!encoded.contains("#"), "a hash must be encoded")
            try check(!encoded.contains("&"), "an ampersand must be encoded")
        },
        CheckCase("form: a password with & and + survives encoding") {
            let encoded = FormEncoding.encode([("password", "a&b+c=d")])
            try checkEqual(encoded, "password=a%26b%2Bc%3Dd")
        },
        CheckCase("cookie: PHPSESSID is extracted from Set-Cookie") {
            let cookie = CookieHeader.sessionCookie(
                from: ["PHPSESSID=abc123def; path=/; HttpOnly"]
            )
            try checkEqual(cookie, "abc123def")
        },
        CheckCase("cookie: other cookies and Expires commas are ignored") {
            let cookie = CookieHeader.sessionCookie(
                from: ["other=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "PHPSESSID=xyz,-abc9; path=/"]
            )
            try checkEqual(cookie, "xyz,-abc9")
        },
        CheckCase("cookie: no PHPSESSID means no session") {
            let cookie = CookieHeader.sessionCookie(from: ["theme=dark; path=/"])
            try checkNil(cookie, "unrelated cookie")
        },
    ]
}

// MARK: - TLS

func trustChecks() -> [CheckCase] {
    let fingerprint = String(repeating: "ab", count: 32)
    return [
        CheckCase("tls: the default policy defers to the system") {
            try checkEqual(decideTrust(presented: fingerprint, policy: .systemDefault), .useDefault)
            try checkEqual(decideTrust(presented: nil, policy: .systemDefault), .useDefault)
        },
        CheckCase("tls: a matching pin is accepted") {
            try checkEqual(
                decideTrust(presented: fingerprint, policy: .pinnedLeaf(sha256: fingerprint)),
                .acceptPinned
            )
        },
        CheckCase("tls: pin comparison is case-insensitive hex") {
            try checkEqual(
                decideTrust(presented: fingerprint.uppercased(), policy: .pinnedLeaf(sha256: fingerprint)),
                .acceptPinned
            )
        },
        CheckCase("tls: a different certificate is rejected, never defaulted") {
            let other = String(repeating: "cd", count: 32)
            try checkEqual(decideTrust(presented: other, policy: .pinnedLeaf(sha256: fingerprint)), .reject)
        },
        CheckCase("tls: a missing certificate under a pin is rejected") {
            try checkEqual(decideTrust(presented: nil, policy: .pinnedLeaf(sha256: fingerprint)), .reject)
        },
        CheckCase("tls: constant-time comparison still compares correctly") {
            try check(constantTimeEqual("abc", "abc"), "equal strings")
            try check(!constantTimeEqual("abc", "abd"), "differing strings")
            try check(!constantTimeEqual("abc", "ab"), "different lengths")
        },
    ]
}

// MARK: - Tokens

func tokenChecks() -> [CheckCase] {
    [
        CheckCase("token: generated tokens are 64 lowercase hex characters") {
            let token = OwnerToken.generate()
            try checkEqual(token.value.count, 64)
            try check(token.value.allSatisfy { $0.isHexDigit && !$0.isUppercase }, "lowercase hex")
        },
        CheckCase("token: two generated tokens differ") {
            try check(OwnerToken.generate().value != OwnerToken.generate().value, "tokens must be random")
        },
        CheckCase("token: malformed values are refused") {
            try checkNil(OwnerToken(value: "short"), "too short")
            try checkNil(OwnerToken(value: String(repeating: "A", count: 64)), "uppercase")
            try checkNil(OwnerToken(value: String(repeating: "z", count: 64)), "non-hex")
        },
        CheckCase("token: neither description nor debugDescription contains the value") {
            let token = OwnerToken.generate()
            try check(!String(describing: token).contains(token.value), "description leaks")
            try check(!String(reflecting: token).contains(token.value), "debugDescription leaks")
            try check(!token.redacted.contains(token.value), "redacted form leaks")
        },
        CheckCase("token: an in-memory store round-trips and deletes") {
            let store = InMemoryTokenStore()
            let token = OwnerToken.generate()
            try checkNil(try store.load(for: "device"))
            try store.save(token, for: "device")
            try checkEqual(try store.load(for: "device"), token)
            try store.delete(for: "device")
            try checkNil(try store.load(for: "device"))
        },
        CheckCase("token: keychain store round-trips when available") {
            #if canImport(Security)
            let store = KeychainTokenStore(service: "io.github.maxrink.e64local.checks.\(UUID().uuidString)")
            let key = "grinder"
            let token = OwnerToken.generate()
            do {
                try store.save(token, for: key)
                let loaded = try store.load(for: key)
                try checkEqual(loaded, token)
                try store.delete(for: key)
                try checkNil(try store.load(for: key))
            } catch let error as TokenStoreError {
                // A headless host without an unlocked keychain cannot run this;
                // the app always can.  Report, do not fail the suite.
                if case .keychainUnavailable = error { return }
                throw error
            }
            #endif
        },
        CheckCase("session: only a plausible session id is accepted") {
            try checkNotNil(VendorSession(sessionID: "abc123"), "normal id")
            try checkNil(VendorSession(sessionID: ""), "empty")
            try checkNil(VendorSession(sessionID: "bad;id"), "semicolon")
            try checkNil(VendorSession(sessionID: "with space"), "space")
        },
        CheckCase("session: the cookie header names PHPSESSID") {
            let session = try checkNotNil(VendorSession(sessionID: "abc123"))
            try checkEqual(session.cookieHeader, "PHPSESSID=abc123")
            try check(!String(describing: session).contains("abc123"), "session id leaks in description")
        },
        CheckCase("session: check_session text is interpreted exactly") {
            try check(VendorLogin.isSessionValid("session_valid\n"), "valid")
            try check(!VendorLogin.isSessionValid("session_invalid\n"), "invalid")
            try check(!VendorLogin.isSessionValid(""), "empty")
        },
    ]
}
