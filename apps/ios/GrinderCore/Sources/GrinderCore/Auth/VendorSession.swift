import Foundation

/// A vendor PHP session, obtained from `login.php`.
///
/// Only the `PHPSESSID` cookie is kept.  It is never written to a cookie store,
/// and it is the first of the two factors every local API route needs.
public struct VendorSession: Sendable, Equatable {
    public let sessionID: String

    public init?(sessionID: String) {
        guard CookieHeader.isPlausibleSessionID(sessionID) else { return nil }
        self.sessionID = sessionID
    }

    public var cookieHeader: String {
        "\(CookieHeader.sessionCookieName)=\(sessionID)"
    }

    /// Never expose the session id in a log line or an error message.
    public var description: String { "«PHP session withheld»" }
    public var debugDescription: String { description }
}

extension VendorSession: CustomDebugStringConvertible {}

/// What the vendor login returned.
public struct LoginOutcome: Sendable, Equatable {
    /// `true` when `check_session` reported `session_valid`, or when the login
    /// page redirected to `index.php` (the vendor's documented success signal).
    public let sessionEstablished: Bool
    public let session: VendorSession?
    /// The `Authorization: Bearer …` header the vendor returns on success.  The
    /// app does not need it, and never stores it.
    public let sawAuthorizationHeader: Bool

    public init(sessionEstablished: Bool, session: VendorSession?, sawAuthorizationHeader: Bool) {
        self.sessionEstablished = sessionEstablished
        self.session = session
        self.sawAuthorizationHeader = sawAuthorizationHeader
    }
}

public enum AuthError: Error, Equatable {
    case wrongPassword
    case noSession
    case sessionExpired
}

extension AuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .wrongPassword:
            return "The Owner password was not accepted. Check the password set on the grinder."
        case .noSession:
            return "The grinder did not open a session."
        case .sessionExpired:
            return "The grinder session expired. Sign in again."
        }
    }
}

/// The vendor login form, in the exact field order e64root uses.
public enum VendorLogin {
    public static func formFields(password: String, userRole: String = "Owner") -> [(name: String, value: String)] {
        [
            ("login", "1"),
            ("requestDeveloper", "1"),
            ("password", password),
            ("userRole", userRole),
        ]
    }

    public static func body(password: String, userRole: String = "Owner") -> Data {
        Data(FormEncoding.encode(formFields(password: password, userRole: userRole)).utf8)
    }

    /// `session_valid` from the pre-session `check_session` route.
    public static func isSessionValid(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines) == "session_valid"
    }
}
