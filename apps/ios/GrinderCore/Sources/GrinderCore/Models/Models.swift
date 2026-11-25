import Foundation

// Response shapes from docs/openapi/local-api.yaml and ondevice/rest_api_dev.php.
//
// Two facts drive the decoding here:
//   * The vendor dispatcher answers HTTP 200 for success and HTTP 400 for every
//     handled failure, with the real code in the body's `errorCode`.
//   * Every DB-backed row value is a string (the module reads rows through
//     `sqlite3 -csv`), so numeric fields are parsed explicitly and a messy
//     value must not fail the whole page.

/// The body `errorCode` values defined by the module.
public enum LocalAPIErrorCode: Int, Sendable {
    case success = 0
    case validation = 400
    case unauthorized = 401
    case forbidden = 403
    case tooLarge = 413
    case server = 500
}

/// A handled failure returned by the module (or the direct dev-gate refusal).
public struct LocalAPIError: Error, Equatable, Sendable {
    public let code: Int
    public let message: String
    public let console: String?

    public init(code: Int, message: String, console: String? = nil) {
        self.code = code
        self.message = message
        self.console = console
    }

    public var localizedCode: LocalAPIErrorCode? { LocalAPIErrorCode(rawValue: code) }

    /// Owner-facing explanation.  `console` is diagnostic text and is never
    /// shown as the primary message.
    public var userMessage: String {
        switch localizedCode {
        case .unauthorized:
            return "The owner token was refused. Re-run setup to install a new token, or check that the token in the Keychain is the one on the grinder."
        case .forbidden:
            return "The grinder refused the request: \(message). The local API needs a development image."
        case .tooLarge:
            return "The request was too large for the grinder."
        case .validation:
            return "The grinder rejected the request: \(message)."
        case .server:
            return "The grinder reported an internal error: \(message)."
        case .success, .none:
            return message
        }
    }
}

extension LocalAPIError: LocalizedError {
    public var errorDescription: String? { userMessage }
}

/// The envelope shared by every route.
public struct Envelope<Data: Decodable & Sendable>: Decodable, Sendable {
    public let success: Bool
    public let errorCode: Int
    public let error: String?
    public let console: String?
    public let data: Data?

    private enum CodingKeys: String, CodingKey {
        case success, errorCode, error, console, data
    }
}

/// Generic JSON helpers shared by the models.  Response values are frequently
/// strings where the schema says integer or boolean (rows come from `sqlite3
/// -csv`), so every scalar is read leniently.
enum JSONValue {
    static func int(from container: KeyedDecodingContainer<AnyCodingKey>, _ key: AnyCodingKey) -> Int? {
        if let value = try? container.decode(Int.self, forKey: key) { return value }
        if let text = try? container.decode(String.self, forKey: key) {
            return Int(text.trimmingCharacters(in: .whitespaces))
        }
        if let double = try? container.decode(Double.self, forKey: key) { return Int(double) }
        return nil
    }

    static func bool(from container: KeyedDecodingContainer<AnyCodingKey>, _ key: AnyCodingKey) -> Bool? {
        if let value = try? container.decode(Bool.self, forKey: key) { return value }
        if let text = try? container.decode(String.self, forKey: key) {
            switch text.lowercased() {
            case "1", "true", "yes": return true
            case "0", "false", "no": return false
            default: return nil
            }
        }
        if let value = try? container.decode(Int.self, forKey: key) { return value != 0 }
        return nil
    }

    static func string(from container: KeyedDecodingContainer<AnyCodingKey>, _ key: AnyCodingKey) -> String? {
        if let value = try? container.decode(String.self, forKey: key) { return value }
        if let value = try? container.decode(Int.self, forKey: key) { return String(value) }
        if let value = try? container.decode(Double.self, forKey: key) { return String(value) }
        return nil
    }
}

/// A DB row: every value is a string, keys are whatever the query returned.
public struct Row: Decodable, Hashable, Sendable, Identifiable {
    public let values: [String: String]

    /// A stable identity for SwiftUI lists, derived from the row's id column
    /// when there is one and from the whole row otherwise.
    public var id: String {
        for key in ["grind_id", "event_id", "alert_id", "portafilter_id", "recipe_index"] {
            if let value = values[key] { return "\(key)=\(value)" }
        }
        return values.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "&")
    }

    public init(values: [String: String]) {
        self.values = values
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        var values: [String: String] = [:]
        for key in container.allKeys {
            values[key.stringValue] = JSONValue.string(from: container, key) ?? ""
        }
        self.values = values
    }

    public subscript(key: String) -> String? { values[key] }

    /// A display order that keeps identity-ish columns first.
    public var orderedColumns: [String] {
        let preferred = [
            "grind_id", "grind_date_time", "grind_weight", "grind_successfull",
            "event_id", "event_date_time", "event_type", "alert_id", "alert_date_time",
            "alert_type", "alert_active", "portafilter_id", "recipe_index", "recipe_type",
        ]
        let ranked = values.keys.sorted { lhs, rhs in
            let l = preferred.firstIndex(of: lhs) ?? preferred.count
            let r = preferred.firstIndex(of: rhs) ?? preferred.count
            return l == r ? lhs < rhs : l < r
        }
        return ranked
    }
}

/// A `Codable` key for decoding objects with arbitrary keys.
struct AnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

/// `capabilities` — the handshake route.
public struct Capabilities: Decodable, Sendable, Equatable {
    public let apiVersion: String
    public let routes: [String]
    public let features: Features
    public let limits: Limits
    /// `data.actions` — the action catalog and policy.
    ///
    /// The device always reports it so an operator can see why an action is not
    /// dispatchable; `features.actions` only says whether the gate is open.  It
    /// is optional here because a firmware without the action layer omits it.
    public let actions: ActionCatalog?
    public let serverTime: Int?
    public let devMode: Bool

    public struct Features: Decodable, Sendable, Equatable {
        public let pagination: Bool
        public let timeFilters: Bool
        public let logRowTypes: String?
        public let recipeExport: String?
        public let csvExport: Bool?
        public let singleRecipe: Bool?
        public let machineIdentity: String?
        public let wssToken: Bool?
        /// True only when the device owner has written an action policy.  This
        /// app never calls an action route, whatever the device reports.
        public let actions: Bool
    }

    public struct Limits: Decodable, Sendable, Equatable {
        public let maxRows: Int
        public let defaultRows: [String: Int]
        public let maxOffset: Int
        public let maxFileBytes: Int
        public let maxRequestBytes: Int

        private enum CodingKeys: String, CodingKey {
            case maxRows, defaultRows, maxOffset, maxFileBytes, maxRequestBytes
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: AnyCodingKey.self)
            maxRows = JSONValue.int(from: container, AnyCodingKey(stringValue: "maxRows")) ?? 5000
            maxOffset = JSONValue.int(from: container, AnyCodingKey(stringValue: "maxOffset")) ?? 1_000_000
            maxFileBytes = JSONValue.int(from: container, AnyCodingKey(stringValue: "maxFileBytes")) ?? 1_048_576
            maxRequestBytes = JSONValue.int(from: container, AnyCodingKey(stringValue: "maxRequestBytes")) ?? 16_384

            var rows: [String: Int] = [:]
            if let raw = try? container.decode([String: AnyCodable2].self, forKey: AnyCodingKey(stringValue: "defaultRows")) {
                for (key, value) in raw {
                    switch value {
                    case .int(let int): rows[key] = int
                    case .double(let double): rows[key] = Int(double)
                    default: break
                    }
                }
            }
            defaultRows = rows
        }
    }
}

/// The lenient scalar used where a route's field may be a number or a string.
enum AnyCodable2: Decodable {
    case int(Int)
    case double(Double)
    case string(String)
    case bool(Bool)
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else {
            self = .string(try container.decode(String.self))
        }
    }
}

/// `machine` — model, firmware and a hashed serial.
public struct Machine: Decodable, Sendable, Equatable {
    public let variant: String
    public let model: String
    public let grinderType: Int?
    public let grinderTypeName: String
    public let grinderSubType: Int?
    public let firmware: String
    public let devMode: Bool
    public let serialPresent: Bool
    public let serialSha256: String?
    public let serialNote: String

    private enum CodingKeys: String, CodingKey {
        case variant, model, grinderType, grinderTypeName, grinderSubType
        case firmware, devMode, serialPresent, serialSha256, serialNote
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        variant = JSONValue.string(from: container, AnyCodingKey(stringValue: "variant")) ?? "unknown"
        model = JSONValue.string(from: container, AnyCodingKey(stringValue: "model")) ?? "unknown"
        grinderType = JSONValue.int(from: container, AnyCodingKey(stringValue: "grinderType"))
        grinderTypeName = JSONValue.string(from: container, AnyCodingKey(stringValue: "grinderTypeName")) ?? "unknown"
        grinderSubType = JSONValue.int(from: container, AnyCodingKey(stringValue: "grinderSubType"))
        firmware = JSONValue.string(from: container, AnyCodingKey(stringValue: "firmware")) ?? ""
        devMode = JSONValue.bool(from: container, AnyCodingKey(stringValue: "devMode")) ?? false
        serialPresent = JSONValue.bool(from: container, AnyCodingKey(stringValue: "serialPresent")) ?? false
        serialSha256 = JSONValue.string(from: container, AnyCodingKey(stringValue: "serialSha256"))
        serialNote = JSONValue.string(from: container, AnyCodingKey(stringValue: "serialNote")) ?? ""
    }
}

/// One page of a log route.
public struct LogPage: Decodable, Sendable, Equatable {
    public let route: String
    public let rows: [Row]
    public let count: Int
    public let limit: Int
    public let offset: Int
    public let since: String?
    public let until: String?
    public let hasMore: Bool
    /// Present when the firmware has no `alert_log` table.
    public let note: String?

    /// Next offset for a page walk, per docs/LOCAL_API.md §5.
    public var nextOffset: Int { offset + count }
}

/// A simple table response (`portafilters`, `recipes`).
public struct RowTable: Decodable, Sendable, Equatable {
    public let route: String
    public let rows: [Row]
    public let count: Int
}

/// `settings` — flat key/value export with omitted keys listed.
public struct SettingsExport: Decodable, Sendable, Equatable {
    public let route: String
    public let settings: [String: String]
    public let redacted: [String]
    public let count: Int

    public var sortedKeys: [String] { settings.keys.sorted() }

    private enum CodingKeys: String, CodingKey { case route, settings, redacted, count }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        route = try container.decode(String.self, forKey: .route)
        redacted = (try? container.decode([String].self, forKey: .redacted)) ?? []
        count = (try? container.decode(Int.self, forKey: .count)) ?? 0
        // PHP serialises an empty map as `[]`; accept both.
        if let map = try? container.decode([String: String].self, forKey: .settings) {
            settings = map
        } else {
            settings = [:]
        }
    }
}

/// `config` — machine config JSON with sensitive values replaced.
public struct ConfigExport: Decodable, Sendable, Equatable {
    public let route: String
    public let config: [String: JSONField]
    public let redacted: [String]
}

/// A value of unknown JSON type, rendered for display without guessing.
public enum JSONField: Decodable, Sendable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case array([JSONField])
    case object([String: JSONField])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONField].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONField].self) {
            self = .object(value)
        } else {
            self = .null
        }
    }

    /// One-line rendering for a list row.
    public var displayText: String {
        switch self {
        case .string(let value): return value
        case .number(let value):
            return value == value.rounded() && abs(value) < 1e15
                ? String(Int(value))
                : String(value)
        case .bool(let value): return value ? "true" : "false"
        case .null: return "null"
        case .array(let values): return values.map(\.displayText).joined(separator: ", ")
        case .object(let values):
            return values.keys.sorted().map { "\($0): \(values[$0]!.displayText)" }.joined(separator: ", ")
        }
    }

    /// Pretty JSON for the detail view.
    public var prettyJSON: String {
        switch self {
        case .string(let value): return "\"\(value)\""
        case .number, .bool, .null: return displayText
        case .array(let values):
            return "[\n" + values.map { "  " + $0.prettyJSON }.joined(separator: ",\n") + "\n]"
        case .object(let values):
            let body = values.keys.sorted()
                .map { "  \"\($0)\": \(values[$0]!.prettyJSON)" }
                .joined(separator: ",\n")
            return "{\n\(body)\n}"
        }
    }
}

/// `file` — one allowlisted file, text or base64.
public struct FileContent: Decodable, Sendable, Equatable {
    public enum Encoding: String, Decodable, Sendable {
        case text
        case base64
    }

    public let path: String
    public let encoding: Encoding
    public let content: String

    /// Decoded bytes (base64) or UTF-8 text bytes.
    public var bytes: Data? {
        switch encoding {
        case .text: return content.data(using: .utf8)
        case .base64: return Data(base64Encoded: content)
        }
    }

    public var byteCount: Int { bytes?.count ?? 0 }
}

/// `ws_token` — a WSS credential.  The app never requests this route; the
/// model exists so an unexpected response is still typed if one ever appears.
public struct WebSocketToken: Decodable, Sendable, Equatable {
    public let token: String
    public let expires: Int
    public let warning: String
}
