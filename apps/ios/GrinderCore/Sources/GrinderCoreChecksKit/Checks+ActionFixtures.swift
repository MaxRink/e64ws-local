import Foundation
import GrinderCore

// Fixtures for the action-layer checks (docs/LOCAL_API.md §12).
//
// Two rules keep these honest:
//
//   * every canned response is the shape the module actually writes, and every
//     refusal message is copied verbatim from `ondevice/rest_api_dev.php`, so a
//     check fails when the client is only correct against invented wording;
//   * the confirm token in the fixtures is an obvious dummy.  No real token is
//     generated, read or printed anywhere in this file.

/// The confirm token every fixture returns.  A dummy: 64 lowercase hex
/// characters spelling a pattern, not a credential.
let fixtureConfirmToken = String(repeating: "0123456789abcdef", count: 4)
let fixtureActionId = "0d6f7e8a-1b2c-4d3e-8f90-1a2b3c4d5e6f"
let fixtureRequestId = "checks-request-0001"
/// Ten minutes out, so a fixture token is inside its TTL whenever the checks
/// run without pinning the suite to one wall-clock date.
let fixtureExpires = Int(Date().timeIntervalSince1970) + 600

/// The destructive gate's refusal, as the module words it.
let destructiveBlocked = "destructive actions are disabled; re-deploy with --enable-destructive-actions"

// MARK: - Stubs

/// A stub that answers by route and records every request.
///
/// One canned response per route: every check here sends at most one request per
/// route, and a check that expects *no* second request asserts it on the
/// recorded request list instead.
actor ActionTransport: Transport {
    private var responses: [String: TransportResponse]
    private(set) var requests: [TransportRequest] = []
    private let failure: TransportError?

    init(_ responses: [String: TransportResponse] = [:], failure: TransportError? = nil) {
        self.responses = responses
        self.failure = failure
    }

    func send(_ request: TransportRequest) async throws -> TransportResponse {
        requests.append(request)
        if let failure { throw failure }
        return responses[Self.route(of: request)]
            ?? jsonResponse("{\"success\":false,\"errorCode\":404,\"error\":\"unknown action\"}")
    }

    nonisolated static func route(of request: TransportRequest) -> String {
        request.url.path.split(separator: "/").last.map(String.init) ?? ""
    }

    func routeNames() -> [String] { requests.map(Self.route(of:)) }

    /// Every recorded body as text, in request order.
    func bodies() -> [String] {
        requests.map { $0.body.flatMap { String(data: $0, encoding: .utf8) } ?? "" }
    }
}

/// A stub that parks the execute request until the check releases it, so a
/// cancel can land while an action is running.  Bounded: if the gate is never
/// opened the request goes through anyway and the check fails on its own
/// assertion instead of hanging.
actor GatedActionTransport: Transport {
    private var responses: [String: TransportResponse]
    private var gateOpen = false
    private var executeWaiting = false
    private(set) var requests: [TransportRequest] = []

    init(_ responses: [String: TransportResponse]) {
        self.responses = responses
    }

    func send(_ request: TransportRequest) async throws -> TransportResponse {
        requests.append(request)
        let route = ActionTransport.route(of: request)
        if route == "action_execute" {
            executeWaiting = true
            var waited = 0
            while !gateOpen && waited < 2_000 {
                try await Task.sleep(nanoseconds: 2_000_000)
                waited += 1
            }
        }
        return responses[route]
            ?? jsonResponse("{\"success\":false,\"errorCode\":404,\"error\":\"unknown action\"}")
    }

    func isExecuteWaiting() -> Bool { executeWaiting }

    func openGate() {
        gateOpen = true
    }
}

// MARK: - Catalog

/// `capabilities.data.actions` as the module builds it (`_actionCapabilities`):
/// every catalog entry is always listed, and `actionRoutes` holds only what the
/// gate would let run.
private func catalogEntryJSON(
    route: String,
    status: String = "implemented",
    risk: String = "state-changing",
    destructive: Bool = false,
    blocked: String? = nil,
    reason: String? = nil
) -> String {
    var parts = [
        "\"route\":\"\(route)\"",
        "\"status\":\"\(status)\"",
        "\"risk\":\"\(risk)\"",
        "\"destructive\":\(destructive)",
        "\"surface\":\"settings\"",
        "\"summary\":\"fixture entry\"",
        "\"evidence\":\"tools/e64root/tests/fixtures/local_api\"",
    ]
    if let blocked { parts.append("\"blocked\":\"\(blocked)\"") }
    if let reason { parts.append("\"reason\":\"\(reason)\"") }
    return "{" + parts.joined(separator: ",") + "}"
}

func catalogDocument(enabled: Bool = true, destructiveEnabled: Bool = false) -> String {
    var entries = [catalogEntryJSON(route: "action_language_set")]
    entries.append(catalogEntryJSON(
        route: "action_recipe_delete",
        risk: "destructive",
        destructive: true,
        blocked: destructiveEnabled ? nil : destructiveBlocked
    ))
    entries.append(catalogEntryJSON(
        route: "action_grind_pause",
        status: "unavailable",
        risk: "actuator",
        reason: "the firmware has no pause command"
    ))

    var routes: [String] = []
    if enabled {
        routes.append("action_language_set")
        if destructiveEnabled { routes.append("action_recipe_delete") }
    }
    let reason = enabled ? "null" : "\"actions are not enabled (policy file missing)\""

    var parts = [
        "\"schema\":\"e64local-api-v1\"",
        "\"enabled\":\(enabled)",
        "\"destructiveEnabled\":\(enabled && destructiveEnabled)",
        "\"reason\":\(reason)",
        "\"actionRoutes\":[" + routes.map { "\"\($0)\"" }.joined(separator: ",") + "]",
        "\"catalog\":[" + entries.joined(separator: ",") + "]",
    ]
    if enabled {
        parts.append(
            "\"policy\":{\"version\":1,"
            + "\"bounds\":{\"targetWeightGr\":{\"min\":0.1,\"max\":50},"
            + "\"grindTimeSec\":{\"min\":0.5,\"max\":60}},"
            + "\"rateLimits\":{\"grind_start\":{\"perMinute\":6,\"perHour\":30}},"
            + "\"tokenTtlSec\":{\"actuator\":60,\"stateChanging\":600,\"destructive\":60},"
            + "\"audit\":{\"file\":\"/db/e64local/audit.jsonl\",\"maxBytes\":1048576,\"keep\":3}}"
        )
    }
    return "{" + parts.joined(separator: ",") + "}"
}

func fixtureCatalog(enabled: Bool = true, destructiveEnabled: Bool = false) throws -> ActionCatalog {
    let data = Data(catalogDocument(enabled: enabled, destructiveEnabled: destructiveEnabled).utf8)
    return try JSONDecoder().decode(ActionCatalog.self, from: data)
}

// MARK: - Route fixtures

func prepareJSON(
    route: String = "action_language_set",
    token: String = fixtureConfirmToken,
    state: String = "prepared",
    idempotent: Bool = false
) -> String {
    "{\"schema\":\"e64local-api-v1\",\"route\":\"action_prepare\","
    + "\"actionId\":\"\(fixtureActionId)\",\"actionRoute\":\"\(route)\","
    + "\"confirmToken\":\"\(token)\",\"expires\":\(fixtureExpires),"
    + "\"expiresAt\":\"2026-01-01T00:01:00Z\",\"state\":\"\(state)\","
    + "\"warnings\":[\"the hopper is below 20 %\"],\"auditId\":\"\(fixtureActionId)\","
    + "\"idempotent\":\(idempotent)}"
}

func executeJSON(
    state: String = "completed",
    result: String = "{\"command\":\"LanguageSet\",\"language\":\"de\"}",
    durationMs: Int = 912
) -> String {
    "{\"schema\":\"e64local-api-v1\",\"route\":\"action_execute\","
    + "\"actionId\":\"\(fixtureActionId)\",\"actionRoute\":\"action_language_set\","
    + "\"state\":\"\(state)\",\"auditId\":\"\(fixtureActionId)\","
    + "\"result\":\(result),\"durationMs\":\(durationMs)}"
}

func statusJSON(
    state: String = "completed",
    errorCode: Int = 0,
    error: String? = nil,
    cancelRequested: Bool = false
) -> String {
    let errorValue = error.map { "\"\($0)\"" } ?? "null"
    return "{\"schema\":\"e64local-api-v1\",\"route\":\"action_status\","
    + "\"actionId\":\"\(fixtureActionId)\",\"actionRoute\":\"action_language_set\","
    + "\"state\":\"\(state)\",\"preparedAt\":\"2026-01-01T00:00:00Z\","
    + "\"expiresAt\":\"2026-01-01T00:01:00Z\",\"startedAt\":\"2026-01-01T00:00:04Z\","
    + "\"finishedAt\":\"2026-01-01T00:00:05Z\",\"durationMs\":912,"
    + "\"errorCode\":\(errorCode),\"error\":\(errorValue),"
    + "\"result\":{\"command\":\"LanguageSet\"},"
    + "\"cancelRequested\":\(cancelRequested),\"auditId\":\"\(fixtureActionId)\"}"
}

func cancelJSON(
    state: String,
    cancelled: Bool,
    stopSent: Bool,
    stopError: String? = nil,
    note: String? = nil
) -> String {
    var parts = [
        "\"schema\":\"e64local-api-v1\"",
        "\"route\":\"action_cancel\"",
        "\"actionId\":\"\(fixtureActionId)\"",
        "\"actionRoute\":\"action_language_set\"",
        "\"state\":\"\(state)\"",
        "\"cancelled\":\(cancelled)",
        "\"stopSent\":\(stopSent)",
    ]
    if let stopError { parts.append("\"stopError\":\"\(stopError)\"") }
    if let note { parts.append("\"note\":\"\(note)\"") }
    return "{" + parts.joined(separator: ",") + "}"
}

func auditJSON(rows: [String]) -> String {
    "{\"schema\":\"e64local-api-v1\",\"route\":\"action_audit\","
    + "\"rows\":[" + rows.joined(separator: ",") + "],"
    + "\"count\":\(rows.count),\"total\":7,\"limit\":50,\"offset\":0,"
    + "\"since\":null,\"until\":null,\"hasMore\":true}"
}

func auditRowJSON(phase: String, result: String, errorCode: Int = 0) -> String {
    "{\"ts\":\"2026-01-01 00:00:00\",\"tsEpoch\":1767225600,\"phase\":\"\(phase)\","
    + "\"route\":\"action_language_set\",\"actionId\":\"\(fixtureActionId)\","
    + "\"requestId\":\"\(fixtureRequestId)\","
    + "\"paramsHash\":\"\(String(repeating: "ab", count: 32))\","
    + "\"result\":\"\(result)\",\"errorCode\":\(errorCode),\"retryAfter\":null,"
    + "\"durationMs\":912,\"client\":{\"addr\":\"192.168.1.20\",\"uaSha256\":null}}"
}

/// A success envelope with one `data` block.
func okEnvelope(_ data: String) -> String {
    "{\"success\":true,\"errorCode\":0,\"data\":\(data)}"
}

/// The refusal envelope.  `retryAfter` sits beside `errorCode`, not inside
/// `data`, exactly as the module writes it.
func refusalEnvelope(
    _ code: Int,
    _ message: String,
    retryAfter: Int? = nil,
    data: String? = nil
) -> String {
    var json = "{\"success\":false,\"errorCode\":\(code),\"error\":\"\(message)\""
    if let retryAfter { json += ",\"retryAfter\":\(retryAfter)" }
    if let data { json += ",\"data\":\(data)" }
    return json + "}"
}

// MARK: - Helpers

/// The action client every check starts from: both factors, a known catalog and
/// a stub transport.
func makeActionClient(
    _ transport: Transport,
    catalog: ActionCatalog? = nil,
    token: OwnerToken? = nil,
    session: VendorSession? = nil
) throws -> ActionClient {
    ActionClient(
        endpoint: try Endpoint(host: "192.168.1.100"),
        transport: transport,
        ownerToken: token ?? OwnerToken.generate(),
        session: session ?? VendorSession(sessionID: "sess123"),
        catalog: catalog
    )
}

/// Run `body` and return the `ActionError` it threw.  A check that expected a
/// refusal never passes because nothing was thrown.
func expectRefusal(
    _ label: String,
    _ body: () async throws -> Void
) async throws -> ActionError {
    do {
        try await body()
    } catch let error as ActionError {
        return error
    }
    throw CheckFailure(
        message: "\(label): expected an ActionError, but nothing was thrown",
        file: #filePath,
        line: #line
    )
}

func decodeJSONObject(_ data: Data) throws -> [String: Any] {
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw CheckFailure(message: "the request body is not a JSON object", file: #filePath, line: #line)
    }
    return object
}
