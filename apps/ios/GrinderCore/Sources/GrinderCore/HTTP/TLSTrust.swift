import Foundation

/// How a device's self-signed HTTPS certificate is treated.
///
/// The default is normal validation.  A device the owner has explicitly opted
/// in for uses a **pinned** trust decision: the leaf certificate's SHA-256 is
/// recorded at setup time and the connection is accepted only when that exact
/// certificate is presented again.  Validation is never turned off globally and
/// a changed certificate is an error the owner sees, not a silent accept.
public enum TLSTrustPolicy: Equatable, Sendable {
    /// Normal system trust evaluation.  This is the default.
    case systemDefault
    /// Accept this device's self-signed certificate by its exact fingerprint.
    case pinnedLeaf(sha256: String)
}

/// The two ways a server-trust challenge can be answered, separated from the
/// URLSession plumbing so the decision is testable.
public enum TrustDecision: Equatable, Sendable {
    /// Fall back to the system's normal trust evaluation.
    case useDefault
    /// Accept the connection, pinned to a known-good certificate.
    case acceptPinned
    /// Cancel; the certificate is not the one the owner opted in for.
    case reject
}

/// Decide how to handle server trust, given the presented leaf fingerprint and
/// the configured policy.
///
/// A pinned policy never falls through to "trust anything": if the fingerprint
/// does not match, the connection is rejected outright, so a replaced or forged
/// certificate cannot be accepted by a default handler afterwards.
public func decideTrust(presented fingerprint: String?, policy: TLSTrustPolicy) -> TrustDecision {
    switch policy {
    case .systemDefault:
        return .useDefault
    case .pinnedLeaf(let expected):
        guard let fingerprint, !fingerprint.isEmpty else { return .reject }
        return constantTimeEqual(
            fingerprint.lowercased().trimmingCharacters(in: .whitespacesAndNewlines),
            expected.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        ) ? .acceptPinned : .reject
    }
}

/// Length-independent comparison, so a wrong pin is not distinguishable by timing.
public func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    var difference = UInt8(left.count == right.count ? 0 : 1)
    for index in 0..<max(left.count, right.count) {
        let a = index < left.count ? left[index] : 0
        let b = index < right.count ? right[index] : 0
        difference |= a ^ b
    }
    return difference == 0
}

/// Fingerprints and identity facts about a TLS peer, for the setup screen.
public struct CertificateInfo: Equatable, Sendable {
    /// SHA-256 over the DER of the leaf certificate, lowercase hex, 64 chars.
    public let sha256: String
    public let commonName: String
    public let issuerCommonName: String
    public let notBefore: Date?
    public let notAfter: Date?

    public init(
        sha256: String,
        commonName: String,
        issuerCommonName: String,
        notBefore: Date?,
        notAfter: Date?
    ) {
        self.sha256 = sha256
        self.commonName = commonName
        self.issuerCommonName = issuerCommonName
        self.notBefore = notBefore
        self.notAfter = notAfter
    }

    /// `AA:BB:…` grouped form, the usual way a fingerprint is compared by eye.
    public var groupedFingerprint: String {
        stride(from: 0, to: sha256.count, by: 2).map { offset -> String in
            let start = sha256.index(sha256.startIndex, offsetBy: offset)
            let end = sha256.index(start, offsetBy: 2, limitedBy: sha256.endIndex) ?? sha256.endIndex
            return String(sha256[start..<end]).uppercased()
        }.joined(separator: ":")
    }
}

/// Inspect a `SecTrust` and describe its leaf certificate, without changing
/// trust.  Used during setup so the owner sees exactly what they opt in for.
public enum CertificateInspection {
    public static func leafCertificate(trust: SecTrust) -> SecCertificate? {
        if #available(iOS 15.0, macOS 12.0, *),
           let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
           let first = chain.first {
            return first
        }
        return nil
    }

    /// The certificate's DER bytes.
    public static func der(of certificate: SecCertificate) -> Data {
        SecCertificateCopyData(certificate) as Data
    }

    /// The leaf certificate's SHA-256 fingerprint.
    public static func fingerprint(of certificate: SecCertificate) -> String {
        Fingerprints.sha256Hex(der(of: certificate))
    }

    public static func info(trust: SecTrust) -> CertificateInfo? {
        guard let certificate = leafCertificate(trust: trust) else { return nil }
        return info(certificate: certificate)
    }

    public static func info(certificate: SecCertificate) -> CertificateInfo? {
        let subject = SecCertificateCopySubjectSummary(certificate) as String?
        return CertificateInfo(
            sha256: fingerprint(of: certificate),
            commonName: subject ?? "",
            issuerCommonName: issuerName(of: certificate),
            notBefore: validityDates(of: certificate)?.0,
            notAfter: validityDates(of: certificate)?.1
        )
    }

    /// Issuer common name from the certificate's OID dictionary.
    private static func issuerName(of certificate: SecCertificate) -> String {
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(
            certificate,
            [kSecOIDX509V1IssuerName as String] as CFArray,
            &error
        ) as? [String: Any] else {
            return ""
        }
        for (_, entry) in values {
            guard let dictionary = entry as? [String: Any] else { continue }
            if let name = dictionary["value"] as? String, !name.isEmpty {
                // `CN=HSG, O=…` style; show the CN when present.
                for component in name.split(separator: ",") {
                    let trimmed = component.trimmingCharacters(in: .whitespaces)
                    if trimmed.uppercased().hasPrefix("CN=") {
                        return String(trimmed.dropFirst(3))
                    }
                }
                return name
            }
        }
        return ""
    }

    /// Validity window from the certificate's OID dictionary.
    private static func validityDates(of certificate: SecCertificate) -> (Date, Date)? {
        var error: Unmanaged<CFError>?
        let keys = [kSecOIDX509V1ValidityNotBefore as String, kSecOIDX509V1ValidityNotAfter as String]
        guard let values = SecCertificateCopyValues(certificate, keys as CFArray, &error)
            as? [String: Any] else {
            return nil
        }
        var notBefore: Date?
        var notAfter: Date?
        for (key, entry) in values {
            guard let dictionary = entry as? [String: Any] else { continue }
            if let date = dictionary["value"] as? Date {
                if key == kSecOIDX509V1ValidityNotBefore as String { notBefore = date }
                if key == kSecOIDX509V1ValidityNotAfter as String { notAfter = date }
            }
        }
        if let notBefore, let notAfter { return (notBefore, notAfter) }
        return nil
    }
}
