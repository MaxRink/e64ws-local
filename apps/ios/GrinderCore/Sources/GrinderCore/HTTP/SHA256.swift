import Foundation
import CryptoKit

/// SHA-256, isolated in its own file so the rest of the package needs only
/// Foundation.  Used for certificate fingerprints and for verifying the bundled
/// PHP module against the repository copy.  CryptoKit is Apple's own crypto and
/// ships on every supported OS, so the package stays free of third-party code
/// while avoiding hand-written cryptography.
enum SHA256Digest {
    static func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

/// Fingerprints in lowercase hex.
public enum Fingerprints {
    public static func sha256Hex(_ data: Data) -> String {
        SHA256Digest.hash(data).map { String(format: "%02x", $0) }.joined()
    }
}
