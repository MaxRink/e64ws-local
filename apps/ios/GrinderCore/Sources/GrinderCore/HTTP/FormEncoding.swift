import Foundation

/// `application/x-www-form-urlencoded` encoding with an explicit field order.
///
/// The ordering matters: the setup injection is sent to `login.php` and the
/// repository's own transport (`tools/e64root/transports.py`) sends
/// `login=1&requestDeveloper=1&password=x&userRole=…`.  PHP decodes the body by
/// name, but keeping the same shape makes a capture diffable against e64root.
///
/// Every byte except RFC 3986 unreserved characters is percent-encoded, so a
/// password (or the injected `userRole` payload, which contains `'`, `;`, `#`
/// and `&`) cannot break the form apart.
public enum FormEncoding {
    private static let unreserved = Set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~".utf8
    )

    public static func encode(_ fields: [(name: String, value: String)]) -> String {
        fields
            .map { "\(percentEncode($0.name))=\(percentEncode($0.value))" }
            .joined(separator: "&")
    }

    /// Percent-encode non-unreserved bytes of the UTF-8 representation.
    public static func percentEncode(_ value: String) -> String {
        var output = String()
        output.reserveCapacity(value.utf8.count)
        for byte in value.utf8 {
            if unreserved.contains(byte) {
                output.append(Character(UnicodeScalar(byte)))
            } else {
                output.append("%")
                output.append(hexDigit(byte >> 4))
                output.append(hexDigit(byte & 0x0F))
            }
        }
        return output
    }

    private static func hexDigit(_ nibble: UInt8) -> Character {
        let scalars = Array("0123456789ABCDEF".unicodeScalars)
        return Character(scalars[Int(nibble)])
    }
}

/// Cookies are handled explicitly, never by a shared cookie store.
///
/// The app keeps exactly one `PHPSESSID` for the one device it is configured
/// for, so it sends that string on every request.  Nothing is written to
/// `HTTPCookieStorage`, which keeps the session scoped to the app process.
public enum CookieHeader {
    public static let sessionCookieName = "PHPSESSID"

    /// Extract the `PHPSESSID` value from one or more `Set-Cookie` headers.
    ///
    /// Only the named cookie is matched, so `Expires=Wed, 21 Oct 2026 …` commas
    /// cannot split a header incorrectly and no other cookie is retained.
    public static func sessionCookie(from setCookieHeaders: [String]) -> String? {
        for header in setCookieHeaders {
            for piece in header.split(separator: ";", omittingEmptySubsequences: true) {
                let trimmed = piece.trimmingCharacters(in: .whitespaces)
                guard let separator = trimmed.firstIndex(of: "=") else { continue }
                let name = trimmed[..<separator].trimmingCharacters(in: .whitespaces)
                guard name.caseInsensitiveCompare(sessionCookieName) == .orderedSame else {
                    continue
                }
                let value = trimmed[trimmed.index(after: separator)...]
                    .trimmingCharacters(in: .whitespaces)
                if isPlausibleSessionID(value) { return value }
            }
        }
        return nil
    }

    /// PHP session ids are `[A-Za-z0-9,-]`; anything else is not a cookie we
    /// should ever send back.
    public static func isPlausibleSessionID(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 256 else { return false }
        return value.unicodeScalars.allSatisfy { scalar in
            (scalar.value < 128)
                && (CharacterSet.alphanumerics.contains(scalar) || scalar == "-" || scalar == ",")
        }
    }
}
