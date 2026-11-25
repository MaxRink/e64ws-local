import Foundation
#if canImport(Security)
import Security
#endif

/// The one device this app is configured for.
///
/// The endpoint is not a secret, but it is also not shared: it lives in the
/// app's own container so a different app cannot read it, and the app has no
/// other storage.
public struct DeviceConfiguration: Codable, Equatable, Sendable {
    /// The host the owner entered.  Shown for display; the app is bound to it.
    public let host: String
    /// The explicit TLS opt-in: the pinned leaf fingerprint, or `nil` for the
    /// system's normal validation.
    public let pinnedCertificateSHA256: String?
    /// When the owner opted in, for the Security screen.
    public let trustedAt: Date?

    public init(host: String, pinnedCertificateSHA256: String? = nil, trustedAt: Date? = nil) {
        self.host = host
        self.pinnedCertificateSHA256 = pinnedCertificateSHA256
        self.trustedAt = trustedAt
    }

    public var trustPolicy: TLSTrustPolicy {
        if let pinned = pinnedCertificateSHA256, !pinned.isEmpty {
            return .pinnedLeaf(sha256: pinned)
        }
        return .systemDefault
    }

    public var endpoint: Endpoint? {
        try? Endpoint(hostAndPort: host)
    }
}

/// Persistence for the device configuration.  A file in the app container is
/// enough for a non-secret host name; the owner token is in the Keychain.
public protocol ConfigurationStore: Sendable {
    func load() throws -> DeviceConfiguration?
    func save(_ configuration: DeviceConfiguration) throws
    func clear() throws
}

public final class FileConfigurationStore: ConfigurationStore, @unchecked Sendable {
    private let url: URL
    private let lock = NSLock()

    public init(url: URL) {
        self.url = url
    }

    public convenience init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? URL(fileURLWithPath: NSTemporaryDirectory())
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        self.init(url: base.appendingPathComponent("e64local-device.json"))
    }

    public func load() throws -> DeviceConfiguration? {
        lock.lock(); defer { lock.unlock() }
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let data = try Data(contentsOf: url)
        return try JSONDecoder.decoder.decode(DeviceConfiguration.self, from: data)
    }

    public func save(_ configuration: DeviceConfiguration) throws {
        lock.lock(); defer { lock.unlock() }
        let data = try JSONEncoder.encoder.encode(configuration)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    public func clear() throws {
        lock.lock(); defer { lock.unlock() }
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }
}

extension JSONDecoder {
    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

extension JSONEncoder {
    static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}

/// The one module binary the app installs.
///
/// In the app this is the bundled resource, verified against the SHA-256 the
/// build pinned.  Accepting only a resource whose digest matches means a
/// tampered bundle cannot push a different module to the grinder.
public struct BundledModule: Sendable {
    public static let resourceName = "rest_api_dev"
    public static let resourceExtension = "php"
    /// SHA-256 of ondevice/rest_api_dev.php at the time this app was built.
    public static let expectedSHA256 = "ca0203d6cee4e0ec241fe37e27ca0d17178def082d103feb774d7ddf93ea4c0c"

    public let data: Data

    public init(data: Data) {
        self.data = data
    }

    public static func load() throws -> BundledModule {
        // Look in the copy resource, then the bundle root, so it works both in
        // SwiftPM resource bundles and when XcodeGen flattens the folder.
        let url = Bundle.module.url(forResource: resourceName, withExtension: resourceExtension)
            ?? Bundle.main.url(forResource: resourceName, withExtension: resourceExtension)
        guard let url else {
            throw BundleError.moduleMissing
        }
        return try load(contentsOf: url)
    }

    public static func load(contentsOf url: URL) throws -> BundledModule {
        let data = try Data(contentsOf: url)
        let digest = Fingerprints.sha256Hex(data)
        guard digest == expectedSHA256 else {
            throw BundleError.digestMismatch(expected: expectedSHA256, actual: digest)
        }
        return BundledModule(data: data)
    }
}

/// The bounded action runner, installed root-owned at
/// `/usr/local/bin/e64local-action-run`.
///
/// It is inert without `/db/e64local/actions.json`, which this app never
/// writes: installing the runner does not make any action reachable.  The
/// digest is pinned for the same reason as the module's.
public struct BundledActionRunner: Sendable {
    public static let resourceName = "e64local_action_run"
    public static let resourceExtension = "php"
    /// SHA-256 of ondevice/e64local_action_run.php at the time this app was built.
    public static let expectedSHA256 = "a6f3ec2ac191e0d13094a221551590041c38b90b7624fb102d8874ad283cb35b"

    public let data: Data

    public init(data: Data) {
        self.data = data
    }

    public static func load() throws -> BundledActionRunner {
        let url = Bundle.module.url(forResource: resourceName, withExtension: resourceExtension)
            ?? Bundle.main.url(forResource: resourceName, withExtension: resourceExtension)
        guard let url else {
            throw BundleError.moduleMissing
        }
        return try load(contentsOf: url)
    }

    public static func load(contentsOf url: URL) throws -> BundledActionRunner {
        let data = try Data(contentsOf: url)
        let digest = Fingerprints.sha256Hex(data)
        guard digest == expectedSHA256 else {
            throw BundleError.digestMismatch(expected: expectedSHA256, actual: digest)
        }
        return BundledActionRunner(data: data)
    }
}

public enum BundleError: Error, Equatable {
    case moduleMissing
    case digestMismatch(expected: String, actual: String)
}

extension BundleError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .moduleMissing:
            return "A bundled device file (the API module or the action runner) is missing from this build."
        case .digestMismatch(let expected, let actual):
            return "A bundled device file does not match its pinned digest (expected \(expected.prefix(16))…, got \(actual.prefix(16))…)."
        }
    }
}
