import Foundation

// Wire shapes for the gated action layer (docs/LOCAL_API.md §12,
// docs/openapi/local-api.yaml, ondevice/rest_api_dev.php).
//
// Three facts drive the decoding here:
//
//   * The five meta routes reuse the read-only envelope, and the vendor
//     dispatcher answers HTTP 400 for every handled failure, so the body's
//     `errorCode` is authoritative.  On a 429 the module also puts
//     `retryAfter` at the *top level* of that body (not inside `data`).
//   * A failed `action_execute` carries the same `data` block as a success, so
//     a client can tell "refused before actuation" from "started and failed"
//     (§12.3).  That block is modelled by `ActionOutcome`.
//   * Records and rows come from JSON files the module writes, but a value may
//     still arrive as a string where the schema says integer, so every scalar
//     is read leniently — the same rule the read-only models follow.
//
// The confirm token is *not* modelled here.  It never leaves `ActionClient`'s
// memory (see `ConfirmToken` in Client/ActionClient.swift), so no type in this
// file can hold, print or persist it.

/// A stored action state.  `cancelling` is the transient answer to a cancel of
/// a running action; it is never a stored record state.
public enum ActionState: Equatable, Sendable {
    case prepared
    case executing
    case completed
    case failed
    case timedOut
    case cancelled
    case expired
    case cancelling
    /// A state this build does not know.  Kept so a newer module cannot make
    /// the client crash or silently read as "completed".
    case unknown(String)

    public init(rawValue: String) {
        switch rawValue {
        case "prepared": self = .prepared
        case "executing": self = .executing
        case "completed": self = .completed
        case "failed": self = .failed
        case "timed_out": self = .timedOut
        case "cancelled": self = .cancelled
        case "expired": self = .expired
        case "cancelling": self = .cancelling
        default: self = .unknown(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .prepared: return "prepared"
        case .executing: return "executing"
        case .completed: return "completed"
        case .failed: return "failed"
        case .timedOut: return "timed_out"
        case .cancelled: return "cancelled"
        case .expired: return "expired"
        case .cancelling: return "cancelling"
        case .unknown(let value): return value
        }
    }

    /// True once the record can no longer execute, so the confirm token is dead.
    public var isTerminal: Bool {
        switch self {
        case .completed, .failed, .timedOut, .cancelled, .expired, .unknown:
            return true
        case .prepared, .executing, .cancelling:
            return false
        }
    }

    public var isSuccess: Bool { self == .completed }
}

/// One action parameter value.
///
/// Restricted to the four scalar shapes and one object, because the module
/// normalises every parameter to a fixed key set and scalar type before
/// hashing: a string where a number is required is a 422, so the client cannot
/// express it.  `settingsEntries` is the only implemented parameter that is an
/// object (ondevice/rest_api_dev.php, `_actionSettingsEntries`).
public indirect enum ActionParam: Encodable, Equatable, Sendable {
    case string(String)
    case int(Int)
    case number(Double)
    case bool(Bool)
    case object([String: ActionParam])

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .string(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .int(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .number(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .bool(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .object(let values):
            var container = encoder.container(keyedBy: AnyCodingKey.self)
            // Sorted, so the same parameters always encode to the same bytes.
            for key in values.keys.sorted() {
                try container.encode(values[key]!, forKey: AnyCodingKey(stringValue: key))
            }
        }
    }
}

// MARK: - Capabilities: the action catalog

/// `capabilities.data.actions` — the catalog and policy the device publishes.
///
/// This is the read shape the read-only client did not model.  The client needs
/// it for one decision it must not guess: whether a route is dispatchable at
/// all.  The module omits a destructive route from `actionRoutes` while the
/// destructive gate is closed, so `actionRoutes` is the device's own answer to
/// "would this run" (§12.1).
public struct ActionCatalog: Decodable, Sendable, Equatable {
    public let schema: String?
    /// True only when `/db/e64local/actions.json` parsed and enabled actions.
    public let enabled: Bool
    /// The second gate.  Off by default; `--enable-destructive-actions` writes it.
    public let destructiveEnabled: Bool
    /// Why the gate is closed, when it is.
    public let reason: String?
    /// Implemented actions the gate would let run right now.
    public let actionRoutes: [String]
    /// Every catalog entry, including the ones that are not dispatchable.
    public let catalog: [ActionCatalogEntry]
    /// Present only when the gate is enabled.
    public let policy: ActionPolicy?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        schema = JSONValue.string(from: container, AnyCodingKey(stringValue: "schema"))
        enabled = JSONValue.bool(from: container, AnyCodingKey(stringValue: "enabled")) ?? false
        destructiveEnabled = JSONValue.bool(from: container, AnyCodingKey(stringValue: "destructiveEnabled")) ?? false
        reason = JSONValue.string(from: container, AnyCodingKey(stringValue: "reason"))
        actionRoutes = (try? container.decode([String].self, forKey: AnyCodingKey(stringValue: "actionRoutes"))) ?? []
        catalog = (try? container.decode([ActionCatalogEntry].self, forKey: AnyCodingKey(stringValue: "catalog"))) ?? []
        policy = try? container.decodeIfPresent(ActionPolicy.self, forKey: AnyCodingKey(stringValue: "policy"))
    }

    public func entry(_ route: String) -> ActionCatalogEntry? {
        catalog.first { $0.route == route }
    }

    /// True only when the device says this route would run right now: the gate
    /// is enabled, the catalog implements it, and `actionRoutes` lists it.
    public func isDispatchable(_ route: String) -> Bool {
        enabled && actionRoutes.contains(route)
    }
}

/// One `capabilities.data.actions.catalog` entry.  The catalog is always
/// readable, so an operator can see *why* a route is not dispatchable.
public struct ActionCatalogEntry: Decodable, Sendable, Equatable {
    public let route: String
    /// `implemented` or `unavailable`.
    public let status: String
    /// `actuator`, `state-changing` or `destructive`.
    public let risk: String
    public let destructive: Bool
    public let surface: String?
    public let summary: String?
    /// Where the action's behaviour was established.  Always present.
    public let evidence: String
    /// Present when `status` is `unavailable`.
    public let reason: String?
    /// Present when the route is implemented but the gate would refuse it.
    public let blocked: String?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        route = JSONValue.string(from: container, AnyCodingKey(stringValue: "route")) ?? ""
        status = JSONValue.string(from: container, AnyCodingKey(stringValue: "status")) ?? "unavailable"
        risk = JSONValue.string(from: container, AnyCodingKey(stringValue: "risk")) ?? "state-changing"
        destructive = JSONValue.bool(from: container, AnyCodingKey(stringValue: "destructive")) ?? false
        surface = JSONValue.string(from: container, AnyCodingKey(stringValue: "surface"))
        summary = JSONValue.string(from: container, AnyCodingKey(stringValue: "summary"))
        evidence = JSONValue.string(from: container, AnyCodingKey(stringValue: "evidence")) ?? ""
        reason = JSONValue.string(from: container, AnyCodingKey(stringValue: "reason"))
        blocked = JSONValue.string(from: container, AnyCodingKey(stringValue: "blocked"))
    }

    public var isImplemented: Bool { status == "implemented" }
}

/// The policy the device reports with an enabled catalog.  Displayed, never
/// enforced here: the module re-reads the policy file on every request.
public struct ActionPolicy: Decodable, Sendable, Equatable {
    public let version: Int
    /// Effective bounds after the policy narrowed the absolute caps.
    public let bounds: [String: ActionBound]
    /// Bucket → the `perMinute`/`perHour` document the owner wrote.
    public let rateLimits: [String: JSONField]
    /// `actuator`, `stateChanging`, `destructive` → seconds.
    public let tokenTtlSec: [String: Int]
    public let audit: ActionAuditPolicy?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        version = JSONValue.int(from: container, AnyCodingKey(stringValue: "version")) ?? 1
        bounds = (try? container.decode([String: ActionBound].self, forKey: AnyCodingKey(stringValue: "bounds"))) ?? [:]
        rateLimits = (try? container.decode([String: JSONField].self, forKey: AnyCodingKey(stringValue: "rateLimits"))) ?? [:]
        var seconds: [String: Int] = [:]
        if let ttl = try? container.decode([String: LenientScalar].self, forKey: AnyCodingKey(stringValue: "tokenTtlSec")) {
            for (key, value) in ttl {
                if let parsed = value.intValue { seconds[key] = parsed }
            }
        }
        tokenTtlSec = seconds
        audit = try? container.decodeIfPresent(ActionAuditPolicy.self, forKey: AnyCodingKey(stringValue: "audit"))
    }
}

/// One effective bound: both ends are already clamped into the absolute range by
/// the module, so the client only displays them.
public struct ActionBound: Decodable, Sendable, Equatable {
    public let min: Double
    public let max: Double

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        min = LenientScalar.double(in: container, AnyCodingKey(stringValue: "min")) ?? 0
        max = LenientScalar.double(in: container, AnyCodingKey(stringValue: "max")) ?? 0
    }
}

/// A scalar that may arrive as a number or as a string, read without failing the
/// whole document: the policy's bounds and TTLs are display data, so a value the
/// client cannot parse must not make the catalog undecodable.
private enum LenientScalar: Decodable {
    case int(Int)
    case double(Double)
    case string(String)
    case other

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else {
            self = .other
        }
    }

    var intValue: Int? {
        switch self {
        case .int(let value): return value
        case .double(let value): return Int(value)
        case .string(let value): return Int(value.trimmingCharacters(in: .whitespaces))
        case .other: return nil
        }
    }

    static func double(in container: KeyedDecodingContainer<AnyCodingKey>, _ key: AnyCodingKey) -> Double? {
        guard let value = try? container.decode(LenientScalar.self, forKey: key) else { return nil }
        switch value {
        case .int(let number): return Double(number)
        case .double(let number): return number
        case .string(let text): return Double(text.trimmingCharacters(in: .whitespaces))
        case .other: return nil
        }
    }
}

/// The audit file's location and rotation, as the device reports it.
public struct ActionAuditPolicy: Decodable, Sendable, Equatable {
    public let file: String?
    public let maxBytes: Int?
    public let keep: Int?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        file = JSONValue.string(from: container, AnyCodingKey(stringValue: "file"))
        maxBytes = JSONValue.int(from: container, AnyCodingKey(stringValue: "maxBytes"))
        keep = JSONValue.int(from: container, AnyCodingKey(stringValue: "keep"))
    }
}

// MARK: - action_prepare

/// The prepared record, as the app may see it: everything except the token.
///
/// `ActionClient.prepare` returns this and keeps the `confirmToken` in its own
/// memory.  There is deliberately no token field, so a view, a log line or an
/// error message cannot leak one.
public struct PreparedAction: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let actionId: String
    public let actionRoute: String
    public let state: ActionState
    /// Unix seconds the token stops working at.
    public let expires: Int
    /// The same instant as the device formatted it.
    public let expiresAt: String
    /// Human-readable warnings, e.g. a precondition that is close to failing.
    public let warnings: [String]
    public let auditId: String?
    /// True when the device answered a repeated `requestId` with the stored
    /// action instead of preparing a new one.
    public let idempotent: Bool

    public init(
        actionId: String,
        actionRoute: String,
        state: ActionState,
        expires: Int,
        expiresAt: String,
        warnings: [String] = [],
        auditId: String? = nil,
        idempotent: Bool = false
    ) {
        self.actionId = actionId
        self.actionRoute = actionRoute
        self.state = state
        self.expires = expires
        self.expiresAt = expiresAt
        self.warnings = warnings
        self.auditId = auditId
        self.idempotent = idempotent
    }

    /// True when the TTL has passed, so the token cannot be spent.
    public func isExpired(now: Date = Date()) -> Bool {
        Double(expires) <= now.timeIntervalSince1970
    }

    public var description: String {
        "prepared \(actionRoute) id=\(actionId) state=\(state.rawValue) expiresAt=\(expiresAt)"
    }

    public var debugDescription: String { description }
}

/// The raw `action_prepare` body, including the token.  Internal: only
/// `ActionClient` may see this, and it strips the token before returning.
struct PreparedRecord: Decodable, Sendable {
    let actionId: String
    let actionRoute: String
    let confirmToken: String
    let expires: Int
    let expiresAt: String
    let state: String
    let warnings: [String]
    let auditId: String?
    let idempotent: Bool

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        actionId = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionId")) ?? ""
        actionRoute = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionRoute")) ?? ""
        confirmToken = JSONValue.string(from: container, AnyCodingKey(stringValue: "confirmToken")) ?? ""
        expires = JSONValue.int(from: container, AnyCodingKey(stringValue: "expires")) ?? 0
        expiresAt = JSONValue.string(from: container, AnyCodingKey(stringValue: "expiresAt")) ?? ""
        state = JSONValue.string(from: container, AnyCodingKey(stringValue: "state")) ?? ""
        warnings = (try? container.decode([String].self, forKey: AnyCodingKey(stringValue: "warnings"))) ?? []
        auditId = JSONValue.string(from: container, AnyCodingKey(stringValue: "auditId"))
        idempotent = JSONValue.bool(from: container, AnyCodingKey(stringValue: "idempotent")) ?? false
    }

    var action: PreparedAction {
        PreparedAction(
            actionId: actionId,
            actionRoute: actionRoute,
            state: ActionState(rawValue: state),
            expires: expires,
            expiresAt: expiresAt,
            warnings: warnings,
            auditId: auditId,
            idempotent: idempotent
        )
    }
}

// MARK: - action_execute

/// What one execution produced.  Also the `data` block of a failed execute, so
/// `state` is the difference between "refused before actuation" (the call threw
/// a refusal and no outcome exists) and "started and failed" (§12.3).
public struct ActionOutcome: Decodable, Sendable, Equatable {
    public let actionId: String
    public let actionRoute: String
    public let state: ActionState
    public let auditId: String?
    /// The action's own report, e.g. `{"command": "StartGrindGbw"}`.  Empty
    /// when the action failed before it could report anything.
    public let result: [String: JSONField]
    public let durationMs: Int?

    public init(
        actionId: String,
        actionRoute: String,
        state: ActionState,
        auditId: String? = nil,
        result: [String: JSONField] = [:],
        durationMs: Int? = nil
    ) {
        self.actionId = actionId
        self.actionRoute = actionRoute
        self.state = state
        self.auditId = auditId
        self.result = result
        self.durationMs = durationMs
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        actionId = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionId")) ?? ""
        actionRoute = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionRoute")) ?? ""
        state = ActionState(rawValue: JSONValue.string(from: container, AnyCodingKey(stringValue: "state")) ?? "")
        auditId = JSONValue.string(from: container, AnyCodingKey(stringValue: "auditId"))
        result = (try? container.decode([String: JSONField].self, forKey: AnyCodingKey(stringValue: "result"))) ?? [:]
        durationMs = JSONValue.int(from: container, AnyCodingKey(stringValue: "durationMs"))
    }

    /// True only when the device reports the action finished.
    public var succeeded: Bool { state.isSuccess }
}

// MARK: - action_status (read-only)

/// The stored record.  `errorCode` is 0 until the action fails.
public struct ActionStatus: Decodable, Sendable, Equatable {
    public let actionId: String
    public let actionRoute: String
    public let state: ActionState
    public let preparedAt: String?
    public let expiresAt: String?
    public let startedAt: String?
    public let finishedAt: String?
    public let durationMs: Int?
    public let errorCode: Int
    public let error: String?
    public let result: [String: JSONField]
    /// True while a cancel has been requested but the steps have not unwound.
    public let cancelRequested: Bool
    public let auditId: String?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        actionId = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionId")) ?? ""
        actionRoute = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionRoute")) ?? ""
        state = ActionState(rawValue: JSONValue.string(from: container, AnyCodingKey(stringValue: "state")) ?? "")
        preparedAt = JSONValue.string(from: container, AnyCodingKey(stringValue: "preparedAt"))
        expiresAt = JSONValue.string(from: container, AnyCodingKey(stringValue: "expiresAt"))
        startedAt = JSONValue.string(from: container, AnyCodingKey(stringValue: "startedAt"))
        finishedAt = JSONValue.string(from: container, AnyCodingKey(stringValue: "finishedAt"))
        durationMs = JSONValue.int(from: container, AnyCodingKey(stringValue: "durationMs"))
        errorCode = JSONValue.int(from: container, AnyCodingKey(stringValue: "errorCode")) ?? 0
        error = JSONValue.string(from: container, AnyCodingKey(stringValue: "error"))
        result = (try? container.decode([String: JSONField].self, forKey: AnyCodingKey(stringValue: "result"))) ?? [:]
        cancelRequested = JSONValue.bool(from: container, AnyCodingKey(stringValue: "cancelRequested")) ?? false
        auditId = JSONValue.string(from: container, AnyCodingKey(stringValue: "auditId"))
    }
}

// MARK: - action_cancel

/// The idempotent answer to a cancel: `cancelled` is true only when nothing was
/// sent, `stopSent` only when the running action was interrupted.
public struct ActionCancel: Decodable, Sendable, Equatable {
    public let actionId: String
    public let actionRoute: String
    public let state: ActionState
    public let cancelled: Bool
    public let stopSent: Bool
    /// Why the stop primitive could not be sent, when it could not.
    public let stopError: String?
    /// Present when the action was already terminal.
    public let note: String?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        actionId = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionId")) ?? ""
        actionRoute = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionRoute")) ?? ""
        state = ActionState(rawValue: JSONValue.string(from: container, AnyCodingKey(stringValue: "state")) ?? "")
        cancelled = JSONValue.bool(from: container, AnyCodingKey(stringValue: "cancelled")) ?? false
        stopSent = JSONValue.bool(from: container, AnyCodingKey(stringValue: "stopSent")) ?? false
        stopError = JSONValue.string(from: container, AnyCodingKey(stringValue: "stopError"))
        note = JSONValue.string(from: container, AnyCodingKey(stringValue: "note"))
    }
}

// MARK: - action_audit (read-only)

/// Who asked: the remote address and the SHA-256 of the user agent, never the
/// user agent itself.
public struct ActionAuditClient: Decodable, Sendable, Equatable {
    public let addr: String
    public let uaSha256: String?

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        addr = JSONValue.string(from: container, AnyCodingKey(stringValue: "addr")) ?? ""
        uaSha256 = JSONValue.string(from: container, AnyCodingKey(stringValue: "uaSha256"))
    }
}

/// One audit line (§12.5).  Parameter **values** are never written; only the
/// canonical hash is, so a row cannot be turned back into a command.
public struct ActionAuditRow: Decodable, Sendable, Equatable, Identifiable {
    /// `prepare`, `refuse`, `execute`, `result`, `timeout` or `cancel`.
    public let phase: String
    public let route: String
    public let ts: String
    public let tsEpoch: Int
    public let actionId: String?
    public let requestId: String?
    /// SHA-256 of the canonical parameters: the only record of what was asked.
    public let paramsHash: String?
    public let result: String?
    public let errorCode: Int
    public let retryAfter: Int?
    public let durationMs: Int?
    public let client: ActionAuditClient?

    public var id: String {
        "\(ts)-\(phase)-\(route)-\(actionId ?? "-")-\(requestId ?? "-")"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        phase = JSONValue.string(from: container, AnyCodingKey(stringValue: "phase")) ?? ""
        route = JSONValue.string(from: container, AnyCodingKey(stringValue: "route")) ?? ""
        ts = JSONValue.string(from: container, AnyCodingKey(stringValue: "ts")) ?? ""
        tsEpoch = JSONValue.int(from: container, AnyCodingKey(stringValue: "tsEpoch")) ?? 0
        actionId = JSONValue.string(from: container, AnyCodingKey(stringValue: "actionId"))
        requestId = JSONValue.string(from: container, AnyCodingKey(stringValue: "requestId"))
        paramsHash = JSONValue.string(from: container, AnyCodingKey(stringValue: "paramsHash"))
        result = JSONValue.string(from: container, AnyCodingKey(stringValue: "result"))
        errorCode = JSONValue.int(from: container, AnyCodingKey(stringValue: "errorCode")) ?? 0
        retryAfter = JSONValue.int(from: container, AnyCodingKey(stringValue: "retryAfter"))
        durationMs = JSONValue.int(from: container, AnyCodingKey(stringValue: "durationMs"))
        client = try? container.decodeIfPresent(ActionAuditClient.self, forKey: AnyCodingKey(stringValue: "client"))
    }
}

/// One page of `action_audit`, newest first, in the same envelope as the log
/// routes (§12.3).
public struct ActionAuditPage: Decodable, Sendable, Equatable {
    public let route: String
    public let rows: [ActionAuditRow]
    public let count: Int
    public let total: Int
    public let limit: Int
    public let offset: Int
    public let since: String?
    public let until: String?
    public let hasMore: Bool

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        route = JSONValue.string(from: container, AnyCodingKey(stringValue: "route")) ?? "action_audit"
        rows = (try? container.decode([ActionAuditRow].self, forKey: AnyCodingKey(stringValue: "rows"))) ?? []
        count = JSONValue.int(from: container, AnyCodingKey(stringValue: "count")) ?? 0
        total = JSONValue.int(from: container, AnyCodingKey(stringValue: "total")) ?? 0
        limit = JSONValue.int(from: container, AnyCodingKey(stringValue: "limit")) ?? 0
        offset = JSONValue.int(from: container, AnyCodingKey(stringValue: "offset")) ?? 0
        since = JSONValue.string(from: container, AnyCodingKey(stringValue: "since"))
        until = JSONValue.string(from: container, AnyCodingKey(stringValue: "until"))
        hasMore = JSONValue.bool(from: container, AnyCodingKey(stringValue: "hasMore")) ?? false
    }

    /// Next offset for a page walk, per docs/LOCAL_API.md §5.
    public var nextOffset: Int { offset + count }
}

/// A validated `action_audit` query.
///
/// Built on `LogQuery` so the date-shape and ordering rules are checked once,
/// then clamped to the audit route's own page cap (1000 rows, not 5000) —
/// ondevice/rest_api_dev.php, `E64LOCAL_ACTION_MAX_AUDIT_PAGE`.
public struct ActionAuditQuery: Equatable, Sendable {
    public static let defaultLimit = 50
    public static let maxLimit = 1000

    public let limit: Int
    public let offset: Int
    public let since: String?
    public let until: String?

    public init(
        limit: Int = ActionAuditQuery.defaultLimit,
        offset: Int = 0,
        since: String? = nil,
        until: String? = nil
    ) throws {
        let base = try LogQuery(limit: limit, offset: offset, since: since, until: until)
        self.limit = min(base.limit, Self.maxLimit)
        self.offset = base.offset
        self.since = base.since
        self.until = base.until
    }
}

// MARK: - Request identifier

/// The `requestId` rules the module enforces before anything else
/// (ondevice/rest_api_dev.php, `_actionValidRequestId`):
/// `^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$`.
public enum ActionRequestId {
    public static let minLength = 8
    public static let maxLength = 64

    public static func isValid(_ value: String) -> Bool {
        guard value.count >= minLength, value.count <= maxLength else { return false }
        guard let first = value.first,
              first.isASCII, first.isLetter || first.isNumber
        else {
            return false
        }
        return value.dropFirst().allSatisfy { character in
            guard character.isASCII else { return false }
            return character.isLetter || character.isNumber || "._-".contains(character)
        }
    }

    /// A fresh id the device accepts.  Idempotency is the caller's choice: this
    /// exists so a single tap has a valid id without inventing one in a view.
    public static func make() -> String {
        UUID().uuidString.lowercased()
    }
}

/// The `actionId` shape the module accepts (`^[0-9a-f-]{36}$`).
public enum ActionIdentifier {
    public static func isValid(_ value: String) -> Bool {
        guard value.count == 36 else { return false }
        return value.allSatisfy { character in
            (character.isHexDigit && !character.isUppercase) || character == "-"
        }
    }
}
