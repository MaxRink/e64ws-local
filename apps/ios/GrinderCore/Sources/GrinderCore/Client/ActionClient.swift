import Foundation

/// The action-layer client: the five meta routes of the gated control surface
/// (docs/LOCAL_API.md §12).
///
/// Design rules, each of which a check pins:
///
///  * **The confirm token never leaves this object.**  `action_prepare` returns
///    it, `execute` sends it once, and then it is dropped.  `PreparedAction` —
///    the only value handed back to a caller — has no token field, and
///    `ConfirmToken` is internal with a redacted `description`, so no view, log
///    line or error message can render one.
///  * **Fail closed before sending.**  An action request without both the owner
///    token and the vendor session is refused here, not by the device.  So is a
///    prepare with no catalog: without `capabilities.data.actions` the client
///    cannot tell a dispatchable route from one the gate would refuse, and
///    guessing is how a destructive route gets through.
///  * **The destructive gate is checked twice.**  Once at prepare, against the
///    catalog the device published, and again at execute, because the device
///    re-reads its policy on every request and the owner may have turned the
///    second gate off in between.
///  * **A single-use token is spent locally too.**  The token is removed from
///    memory before the bytes are sent, and put back only for the refusals the
///    module emits *before* it claims the record (429, 503) or for a transport
///    failure.  The module's exclusive `prepared → executing` claim is what
///    makes a double actuation impossible; this is only hygiene.
///  * **A reboot is not a slowdown.**  A token is bound to the kernel boot id,
///    so a 409 that mentions the boot binding is reported as `.rebooted` and the
///    token is dropped rather than retried (§12.4 rule 3).
///
/// What this client does **not** do: it never writes state to disk, never logs,
/// and never mints a WSS credential.  The action identifier is a value of a
/// request field, never an HTTP path.
public actor ActionClient {
    /// The five action routes.  An action identifier such as
    /// `action_grind_start_gbw` is a value of `route` inside `action_prepare`,
    /// never a path, so it is not in this set.
    public static let metaRoutes: Set<String> = [
        "action_prepare", "action_execute", "action_status", "action_cancel", "action_audit",
    ]

    private let endpoint: Endpoint
    private let transport: Transport
    private let ownerToken: OwnerToken?
    private let session: VendorSession?
    /// The catalog from the last `capabilities` read.
    private var catalog: ActionCatalog?
    /// Prepared actions whose token is still live, keyed by `actionId`.
    /// The token exists here and nowhere else.
    private var pending: [String: PendingAction] = [:]
    /// The last 429 the device sent, so a screen can count the wait down.
    private var rateLimit: (seconds: Int, at: Date)?

    public init(
        endpoint: Endpoint,
        transport: Transport,
        ownerToken: OwnerToken? = nil,
        session: VendorSession? = nil,
        catalog: ActionCatalog? = nil
    ) {
        self.endpoint = endpoint
        self.transport = transport
        self.ownerToken = ownerToken
        self.session = session
        self.catalog = catalog
    }

    // MARK: - Catalog and local state

    /// Adopt the catalog from a `capabilities` read.  Passing `nil` (a firmware
    /// without the action layer) makes every prepare refuse.
    public func updateCatalog(_ catalog: ActionCatalog?) {
        self.catalog = catalog
    }

    /// Adopt the catalog straight from the handshake document, which is how the
    /// app wires it: one read, one decision.
    public func updateCatalog(from capabilities: Capabilities) {
        self.catalog = capabilities.actions
    }

    public var knownCatalog: ActionCatalog? { catalog }

    /// Routes the device says it would run right now, if a catalog is known.
    public func dispatchableRoutes() -> [String] {
        catalog?.actionRoutes ?? []
    }

    /// Actions whose confirm token is still held and still inside its TTL.
    public func pendingActionIds(now: Date = Date()) -> [String] {
        pending.filter { !$0.value.isExpired(now: now) }.keys.sorted()
    }

    /// Drop every held token.  For the app going to the background: a token is
    /// good for 60 s (actuator) or 600 s (state-changing), and nothing is gained
    /// by keeping one across a suspension.
    public func forgetPending() {
        pending.removeAll()
    }

    /// Seconds the owner still has to wait, if the device rate-limited us and
    /// the wait has not run out.
    public func retryAfterSeconds(now: Date = Date()) -> Int? {
        guard let rateLimit else { return nil }
        let elapsed = Int(now.timeIntervalSince(rateLimit.at))
        let remaining = rateLimit.seconds - max(0, elapsed)
        return remaining > 0 ? remaining : nil
    }

    // MARK: - action_prepare

    /// Validate one action and hold its confirm token.
    ///
    /// Nothing is actuated here and nothing is returned that could be replayed:
    /// the token stays in this actor's memory.
    public func prepare(
        route: String,
        params: [String: ActionParam] = [:]
    ) async throws -> PreparedAction {
        try await prepare(route: route, params: params, requestId: ActionRequestId.make())
    }

    public func prepare(
        route: String,
        params: [String: ActionParam] = [:],
        requestId: String
    ) async throws -> PreparedAction {
        try checkBothFactors()
        guard ActionRequestId.isValid(requestId) else {
            throw ActionError.invalidRequestId(
                "“\(requestId)” is not a valid requestId (8–64 characters: A-Z a-z 0-9 . _ -)"
            )
        }
        let catalog = try requireCatalog()
        guard let entry = catalog.entry(route) else {
            throw ActionError.unknownRoute("“\(route)” is not in the action catalog")
        }
        guard entry.isImplemented else {
            // 422 on the device; refuse it here without spending the round trip.
            throw ActionError.unavailable(
                "\(route) is reported as unavailable: \(entry.reason ?? "no reason given")"
            )
        }
        guard catalog.enabled else {
            throw ActionError.gateClosed(
                catalog.reason ?? "actions are not enabled on this grinder"
            )
        }
        guard !entry.destructive || catalog.destructiveEnabled else {
            throw ActionError.destructiveGateClosed(
                entry.blocked ?? "destructive actions are disabled on this grinder"
            )
        }
        guard catalog.isDispatchable(route) else {
            throw ActionError.notDispatchable(
                "the grinder does not list \(route) as dispatchable right now"
            )
        }

        let reply: ActionReply<PreparedRecord> = try await post(
            "action_prepare",
            body: PrepareBody(route: route, params: params, requestId: requestId)
        )
        guard let record = reply.data, reply.errorCode == 0 else {
            throw refusal(for: reply)
        }
        guard ActionIdentifier.isValid(record.actionId) else {
            throw ActionError.unexpectedResponse("the grinder returned a malformed actionId")
        }
        guard let token = ConfirmToken(value: record.confirmToken) else {
            throw ActionError.unexpectedResponse("the grinder returned a malformed confirm token")
        }
        pending[record.actionId] = PendingAction(
            token: token,
            route: route,
            destructive: entry.destructive,
            expires: record.expires
        )
        return record.action
    }

    // MARK: - action_execute

    /// Execute one prepared action.  The token is spent here and never reused.
    ///
    /// A refusal that the module emits before it claims the record (429, 503)
    /// leaves the action executable, so the token is put back; every other
    /// refusal, and success, consumes it.
    public func execute(actionId: String) async throws -> ActionOutcome {
        try checkBothFactors()
        guard let held = pending.removeValue(forKey: actionId) else {
            throw ActionError.noPendingAction(
                "no confirm token is held for \(actionId); prepare the action again"
            )
        }
        if held.isExpired() {
            throw ActionError.conflict("the confirm token for \(actionId) has expired")
        }
        // The gate can close between prepare and execute.  The device re-reads its
        // policy on every request, so refuse here rather than spend the token on a
        // call the device will answer with 403.
        if held.destructive, let catalog, !catalog.destructiveEnabled {
            throw ActionError.destructiveGateClosed(
                "destructive actions were disabled after this action was prepared"
            )
        }
        if let catalog, !catalog.isDispatchable(held.route) {
            throw ActionError.notDispatchable(
                "the grinder stopped offering \(held.route) after this action was prepared"
            )
        }

        let reply: ActionReply<ActionOutcome>
        do {
            reply = try await post(
                "action_execute",
                body: ExecuteBody(actionId: actionId, confirmToken: held.token.value)
            )
        } catch {
            // The request may not have arrived, so the record may still be
            // prepared: keep the token so a retry is possible.  A retry after a
            // request that *did* arrive is refused 409 by the module's claim.
            pending[actionId] = held
            throw error
        }

        if let outcome = reply.data, reply.errorCode != 0 {
            // Started and failed: the device sent the record back with the error.
            throw ActionError.executionFailed(
                outcome: outcome,
                code: reply.errorCode,
                message: reply.error ?? "the action failed"
            )
        }
        if reply.errorCode == 0, let outcome = reply.data {
            return outcome
        }

        let error = refusal(for: reply)
        if error.isRetriable {
            pending[actionId] = held
        }
        throw error
    }

    /// Convenience for a caller that kept the prepared record it was given.
    public func execute(_ prepared: PreparedAction) async throws -> ActionOutcome {
        try await execute(actionId: prepared.actionId)
    }

    // MARK: - action_status (read-only)

    public func status(actionId: String) async throws -> ActionStatus {
        try checkBothFactors()
        guard ActionIdentifier.isValid(actionId) else {
            throw ActionError.invalidActionId("“\(actionId)” is not an action identifier")
        }
        let reply: ActionReply<ActionStatus> = try await post(
            "action_status",
            body: IdentifierBody(actionId: actionId)
        )
        guard let status = reply.data, reply.errorCode == 0 else {
            throw refusal(for: reply)
        }
        return status
    }

    // MARK: - action_cancel

    /// Cancel one action.  Idempotent on the device: a prepared action becomes
    /// `cancelled` and nothing is sent, an executing action gets its stop
    /// primitive, and a terminal action is returned unchanged.
    ///
    /// Any cancel that the device accepts drops the held token, because a
    /// cancelled or interrupted action can never be executed again.
    public func cancel(actionId: String) async throws -> ActionCancel {
        try checkBothFactors()
        guard ActionIdentifier.isValid(actionId) else {
            throw ActionError.invalidActionId("“\(actionId)” is not an action identifier")
        }
        let reply: ActionReply<ActionCancel> = try await post(
            "action_cancel",
            body: IdentifierBody(actionId: actionId)
        )
        guard let cancel = reply.data, reply.errorCode == 0 else {
            throw refusal(for: reply)
        }
        pending.removeValue(forKey: actionId)
        return cancel
    }

    // MARK: - action_audit (read-only)

    /// Read the audit trail, newest first.  Rows carry the canonical parameter
    /// hash, never a parameter value (§12.5).
    public func audit(query: ActionAuditQuery? = nil) async throws -> ActionAuditPage {
        try checkBothFactors()
        let query = try query ?? ActionAuditQuery(limit: ActionAuditQuery.defaultLimit)
        let reply: ActionReply<ActionAuditPage> = try await post(
            "action_audit",
            body: AuditBody(
                limit: query.limit,
                offset: query.offset,
                since: query.since,
                until: query.until
            )
        )
        guard let page = reply.data, reply.errorCode == 0 else {
            throw refusal(for: reply)
        }
        return page
    }

    // MARK: - Preconditions

    /// Both factors, refused before anything is sent.  The module answers 401
    /// for a missing token and the vendor dispatcher excludes a mobile-app
    /// session with 403, so the client reports the same two outcomes.
    private func checkBothFactors() throws {
        guard ownerToken != nil else {
            throw ActionError.unauthorized("the owner token is required for every action route")
        }
        guard session != nil else {
            throw ActionError.forbidden("a vendor session is required for every action route")
        }
    }

    private func requireCatalog() throws -> ActionCatalog {
        guard let catalog else {
            throw ActionError.catalogUnavailable(
                "read capabilities first: without the action catalog the app cannot tell a dispatchable action from one the gate would refuse"
            )
        }
        return catalog
    }

    // MARK: - Requests

    private func post<T: Decodable & Sendable>(
        _ route: String,
        body: some Encodable
    ) async throws -> ActionReply<T> {
        guard Self.metaRoutes.contains(route) else {
            throw ActionError.unexpectedResponse("“\(route)” is not an action route")
        }
        var headers: [String: String] = [
            "Content-Type": "application/json",
            "Accept": "application/json",
        ]
        // The header is the only place the owner token is sent, so it is never
        // duplicated into a request body.
        if let token = ownerToken {
            headers[LocalAPI.tokenHeader] = token.value
        }
        if let session {
            headers["Cookie"] = session.cookieHeader
        }

        let response = try await transport.send(
            TransportRequest(
                method: "POST",
                url: endpoint.url(path: "/rest_api/\(route)"),
                headers: headers,
                body: try JSONEncoder().encode(body)
            )
        )
        guard !response.body.isEmpty else {
            throw ActionError.unexpectedResponse("the grinder returned an empty body")
        }
        do {
            let envelope = try JSONDecoder().decode(ActionEnvelope<T>.self, from: response.body)
            return ActionReply(
                data: envelope.data,
                errorCode: envelope.errorCode,
                error: envelope.error,
                retryAfter: envelope.retryAfter
            )
        } catch {
            // A refusal whose `data` block is a shape this build does not model
            // must still be classified, so retry the envelope without it.
            if let bare = try? JSONDecoder().decode(ActionEnvelope<JSONField>.self, from: response.body) {
                return ActionReply(
                    data: nil,
                    errorCode: bare.errorCode,
                    error: bare.error,
                    retryAfter: bare.retryAfter
                )
            }
            throw ActionError.unexpectedResponse(error.localizedDescription)
        }
    }

    /// Map the module's `errorCode` onto a typed refusal (§12.7).
    ///
    /// Two of these decisions read the device's own message, because the module
    /// does not give a distinct code: the boot-binding refusals are both 409,
    /// and an unavailable catalog entry is 422 like a bad parameter.  The exact
    /// strings are pinned by a check against `ondevice/rest_api_dev.php`, so a
    /// wording change fails the checks instead of silently reclassifying.
    private func refusal<T>(for reply: ActionReply<T>) -> ActionError {
        let message = reply.error ?? "request failed"
        let lower = message.lowercased()
        switch reply.errorCode {
        case 400:
            return .malformedRequest(message)
        case 401:
            return .unauthorized(message)
        case 403:
            if lower.contains("destructive actions are disabled") {
                return .destructiveGateClosed(message)
            }
            return .forbidden(message)
        case 404:
            return .unknownRoute(message)
        case 409:
            // "the device has rebooted since this action was prepared" and
            // "the prepared action carries no boot id" are both the boot bind.
            if lower.contains("reboot") || lower.contains("boot id") {
                return .rebooted(message)
            }
            return .conflict(message)
        case 422:
            if lower.hasPrefix("action unavailable") {
                return .unavailable(message)
            }
            return .invalidParameters(message)
        case 429:
            let seconds = max(1, reply.retryAfter ?? 1)
            rateLimit = (seconds, Date())
            return .rateLimited(retryAfterSeconds: seconds)
        case 503:
            return .runnerUnavailable(message)
        case 504:
            return .timedOut(message)
        default:
            return .rejected(code: reply.errorCode, message: message)
        }
    }
}

/// What one action route answered, before it is turned into a value or a typed
/// refusal.
private struct ActionReply<T> {
    let data: T?
    let errorCode: Int
    let error: String?
    let retryAfter: Int?
}

/// The shared action envelope.  `retryAfter` is at the top level of the body,
/// beside `errorCode`, not inside `data` (ondevice/rest_api_dev.php, the 429
/// branch of `_handleActionPrepare`).
private struct ActionEnvelope<Data: Decodable & Sendable>: Decodable, Sendable {
    let success: Bool
    let errorCode: Int
    let error: String?
    let console: String?
    let retryAfter: Int?
    let data: Data?
}

/// One confirm token, held in memory by `ActionClient` and nowhere else.
///
/// Internal on purpose: there is no public initializer and no public accessor,
/// so app code cannot hold one, copy it into a view model or render it.
/// `description` and `debugDescription` are redacted, so an accidental
/// interpolation cannot print it either.
struct ConfirmToken: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    static let hexLength = 64

    let value: String

    init?(value: String) {
        guard value.count == Self.hexLength,
              value.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            return nil
        }
        self.value = value
    }

    var description: String { "«confirm token withheld»" }
    var debugDescription: String { description }
}

/// A prepared action whose token this client still holds.
private struct PendingAction: Sendable {
    let token: ConfirmToken
    let route: String
    let destructive: Bool
    /// Unix seconds.
    let expires: Int

    func isExpired(now: Date = Date()) -> Bool {
        Double(expires) <= now.timeIntervalSince1970
    }
}

// MARK: - Request bodies

// Separate types per route so a field can never be added to the wrong body, and
// so an absent optional is really absent: the synthesised encoder skips a nil.

private struct PrepareBody: Encodable {
    let route: String
    let params: [String: ActionParam]
    let requestId: String
}

private struct ExecuteBody: Encodable {
    let actionId: String
    let confirmToken: String
}

private struct IdentifierBody: Encodable {
    let actionId: String
}

private struct AuditBody: Encodable {
    let limit: Int
    let offset: Int
    let since: String?
    let until: String?
}

// MARK: - Failures

/// Every way an action route can be refused, typed.
///
/// The device is the authority for all of these except the `catalog*`,
/// `destructiveGateClosed` and `noPendingAction` cases, which the client decides
/// before sending anything.
public enum ActionError: Error, Equatable, Sendable {
    /// 401 — the owner token is missing or wrong.
    case unauthorized(String)
    /// 403 — the gate is closed, the session is a mobile-app session, the token
    /// does not match, or the name is one the API excludes by construction.
    case forbidden(String)
    /// 403 — the second gate is closed.  Refused before sending when the
    /// catalog says so.
    case destructiveGateClosed(String)
    /// The catalog says the first gate is closed.
    case gateClosed(String)
    /// The catalog exists but does not list this route as runnable.
    case notDispatchable(String)
    /// No catalog has been read, so nothing can be dispatched safely.
    case catalogUnavailable(String)
    /// 404 — an action identifier this build does not know.
    case unknownRoute(String)
    /// 422 — the catalog entry is `unavailable`.
    case unavailable(String)
    /// 422 — a parameter, or its value, was refused.
    case invalidParameters(String)
    /// 400 — the request was malformed, which is this app's bug, not the owner's.
    case malformedRequest(String)
    /// 409 — the device rebooted since prepare, or the record carries no boot
    /// id, so the token can never execute.
    case rebooted(String)
    /// 409 — replay, expiry, unsafe state or an idempotency conflict.
    case conflict(String)
    /// 429 — rate limited; `retryAfter` seconds, from the body's top level.
    case rateLimited(retryAfterSeconds: Int)
    /// 503 — the runner, the sudoers rule or the rate-limit state is unusable.
    case runnerUnavailable(String)
    /// 504 — the hard timeout fired and the stop primitive was attempted.
    case timedOut(String)
    /// The action started and then failed.  `outcome.state` is the device's
    /// record, which is what separates this from a refusal, and `code` is the
    /// `errorCode` that came with it.
    case executionFailed(outcome: ActionOutcome, code: Int, message: String)
    /// The client holds no token for that action: prepare it first.
    case noPendingAction(String)
    case invalidRequestId(String)
    case invalidActionId(String)
    /// A refusal this build does not map to a named case.
    case rejected(code: Int, message: String)
    /// The reply could not be read at all.
    case unexpectedResponse(String)

    /// True when the same token can be sent again: the module refuses these
    /// before it claims the record as `executing`.
    public var isRetriable: Bool {
        switch self {
        case .rateLimited, .runnerUnavailable:
            return true
        default:
            return false
        }
    }

    /// True when the action can no longer execute whatever happens.
    public var isTerminal: Bool {
        switch self {
        case .rebooted, .conflict, .executionFailed, .timedOut:
            return true
        default:
            return false
        }
    }

    /// The device's `errorCode`, when the device gave one.
    public var errorCode: Int? {
        switch self {
        case .malformedRequest: return 400
        case .unauthorized: return 401
        case .forbidden, .destructiveGateClosed, .gateClosed, .notDispatchable:
            return 403
        case .unknownRoute: return 404
        case .rebooted, .conflict: return 409
        case .unavailable, .invalidParameters: return 422
        case .rateLimited: return 429
        case .runnerUnavailable: return 503
        case .timedOut: return 504
        case .rejected(let code, _): return code
        case .executionFailed(_, let code, _): return code
        case .catalogUnavailable, .noPendingAction, .invalidRequestId, .invalidActionId,
             .unexpectedResponse:
            return nil
        }
    }
}

extension ActionError: LocalizedError {
    public var errorDescription: String? { userMessage }

    /// Owner-facing explanation.  `console` and diagnostic text are never shown
    /// as the primary message; nothing here can contain a confirm token, because
    /// no case carries one.
    public var userMessage: String {
        switch self {
        case .unauthorized(let detail):
            return "The grinder refused the owner token: \(detail). Re-run setup to install a token this phone holds."
        case .forbidden(let detail):
            return "The grinder refused the action request: \(detail)."
        case .destructiveGateClosed(let detail):
            return "Destructive actions are switched off on this grinder: \(detail)"
        case .gateClosed(let detail):
            return "The action gate is closed on this grinder: \(detail)"
        case .notDispatchable(let detail):
            return "This grinder is not offering that action right now: \(detail)"
        case .catalogUnavailable(let detail):
            return "The action catalog has not been read yet: \(detail)"
        case .unknownRoute(let detail):
            return "Unknown action: \(detail)"
        case .unavailable(let detail):
            return "That action cannot run on this grinder: \(detail)"
        case .invalidParameters(let detail):
            return "The grinder rejected the parameters: \(detail)"
        case .malformedRequest(let detail):
            return "The request was malformed, so nothing was started: \(detail)"
        case .rebooted(let detail):
            return "The grinder restarted after this action was prepared, so it can never run: \(detail)"
        case .conflict(let detail):
            return "The action is no longer in a state that allows it: \(detail)"
        case .rateLimited(let seconds):
            return "Slow down: the grinder is rate limiting this action for another \(seconds) s."
        case .runnerUnavailable(let detail):
            return "The action runner is unavailable, so nothing was started: \(detail)"
        case .timedOut(let detail):
            return "The action timed out and the grinder was told to stop: \(detail)"
        case .executionFailed(let outcome, let code, let message):
            return "The action started and then failed (\(outcome.state.rawValue), \(code)): \(message)"
        case .noPendingAction(let detail):
            return "Nothing to execute: \(detail)"
        case .invalidRequestId(let detail), .invalidActionId(let detail):
            return detail
        case .rejected(let code, let message):
            return "The grinder refused the action (\(code)): \(message)"
        case .unexpectedResponse(let detail):
            return "The grinder returned an unexpected response: \(detail)"
        }
    }
}
