import Foundation

/// The log routes the app exposes, and the request parameters they accept.
///
/// Limits and filter forms mirror docs/LOCAL_API.md §5 and §6; the client
/// validates before sending so a bad request never reaches the device.
public enum LogKind: String, CaseIterable, Identifiable, Sendable {
    case grind = "grind_log"
    case service = "service_log"
    case alert = "alert_log"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .grind: return "Grinds"
        case .service: return "Service"
        case .alert: return "Alerts"
        }
    }

    public var defaultLimit: Int {
        switch self {
        case .grind: return 20
        case .service, .alert: return 500
        }
    }
}

/// A validated log query.  `since`/`until` accept a date, a date-time or Unix
/// seconds, matching the module; they are passed through as given and only
/// checked for shape and ordering.
public struct LogQuery: Equatable, Sendable {
    public static let maxLimit = 5000
    public static let maxOffset = 1_000_000

    public let limit: Int
    public let offset: Int
    public let since: String?
    public let until: String?

    public init(
        limit: Int = 20,
        offset: Int = 0,
        since: String? = nil,
        until: String? = nil
    ) throws {
        self.limit = min(max(1, limit), Self.maxLimit)
        self.offset = min(max(0, offset), Self.maxOffset)
        self.since = try Self.check(since)
        self.until = try Self.check(until)
        if let since = self.since, let until = self.until,
           Self.sortKey(since) > Self.sortKey(until) {
            throw QueryError.sinceAfterUntil
        }
    }

    public var isEmpty: Bool { since == nil && until == nil }

    /// Body keys, restricted to what the route documents.
    public func bodyEntries() -> [(String, Int?)] {
        [("limit", limit), ("offset", offset)]
    }

    private static func check(_ value: String?) throws -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespaces), !value.isEmpty else {
            return nil
        }
        if value.allSatisfy({ $0.isNumber }), value.count <= 10 {
            // Unix seconds, as the module accepts.
            return value
        }
        // `YYYY-MM-DD` with an optional ` HH:MM:SS` or `THH:MM:SS` time.
        let normalized = value.replacingOccurrences(of: "T", with: " ")
        let parts = normalized.split(separator: " ")
        guard let date = parts.first, date.count == 10, date.contains("-") else {
            throw QueryError.invalidFilter(value)
        }
        let dateParts = date.split(separator: "-").compactMap { Int($0) }
        guard dateParts.count == 3, dateParts[0] >= 1970, dateParts[0] <= 2100,
              (1...12).contains(dateParts[1]), (1...31).contains(dateParts[2])
        else {
            throw QueryError.invalidFilter(value)
        }
        if parts.count == 2 {
            let timeParts = parts[1].split(separator: ":").compactMap { Int($0) }
            guard timeParts.count == 3,
                  (0...23).contains(timeParts[0]),
                  (0...59).contains(timeParts[1]),
                  (0...59).contains(timeParts[2])
            else {
                throw QueryError.invalidFilter(value)
            }
        }
        return value
    }

    /// Comparable form so `since <= until` can be checked client-side.
    private static func sortKey(_ value: String) -> String {
        if value.allSatisfy({ $0.isNumber }), value.count <= 10 {
            return String(format: "%020d", Int(value) ?? 0)
        }
        return value.replacingOccurrences(of: "T", with: " ")
    }
}

public enum QueryError: Error, Equatable {
    case invalidFilter(String)
    case sinceAfterUntil
}

extension QueryError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidFilter(let value):
            return "“\(value)” is not a valid time filter. Use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds."
        case .sinceAfterUntil:
            return "The start time is after the end time."
        }
    }
}

/// The paths the `file` route may read.
///
/// The module enforces this with `realpath` (docs/LOCAL_API.md §4.10): exact
/// paths only, plus regular files below `/log`.  The client repeats the same
/// restriction so an invalid path is refused before it is sent, and so a screen
/// cannot offer a path the device will reject.
public enum FileAllowlist {
    public static let exactPaths = [
        "/etc/issue",
        "/tmp/FirmwareUpdateState.json",
    ]

    public static func isAllowed(_ path: String) -> Bool {
        guard !path.isEmpty, path.hasPrefix("/"), !path.contains("\0"), path.count < 512 else {
            return false
        }
        // Reject traversal and odd spellings outright; the device resolves them,
        // so a naive prefix check would be misleading.
        guard !path.contains(".."), !path.contains("//"), !path.hasSuffix("/") else {
            return false
        }
        if exactPaths.contains(path) { return true }
        guard path.hasPrefix("/log/"), path.count > "/log/".count else {
            return false
        }
        // Single-component file names below /log, which is what the device's
        // resolved-parent check permits.
        let name = String(path.dropFirst("/log/".count))
        guard !name.isEmpty, !name.contains("/"), !name.hasPrefix(".") else {
            return false
        }
        return true
    }

    /// Paths offered by the UI, plus anything the owner types that is allowed.
    public static var suggestedPaths: [String] {
        exactPaths + ["/log/messages"]
    }
}
