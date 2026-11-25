import Foundation
import GrinderCore

/// The gated action surface, driven by the shipped `ActionClient`.
///
/// The fixture models two peers, and the suite reads which one it is talking to
/// from `capabilities.data.actions` rather than from its own configuration:
///
///  * **gate open** (`--enable-actions`) — the five meta routes really run.  This
///    is the path the harness drives: `prepare → execute → status → audit` on a
///    non-destructive action with a live confirm token, cancel-before-execute on
///    a second prepared action, and a destructive route refused by the second
///    gate while `destructiveEnabled` is false.
///  * **gate closed** (no flag, the state of a shipped image and of a grinder set
///    up by this app) — every meta route is refused 403.  `prepare` and `execute`
///    are refused by the client before a byte is sent, and `status`, `cancel` and
///    `audit` are refused by the device and classified by the client's typed
///    `refusal` mapping.
///
/// Both branches assert behaviour, neither skips: the branch is a property of the
/// peer, and the suite always states which one it proved.
enum ActionSuite {
    /// A UUID-shaped identifier the fixture has never prepared, so a refusal can
    /// only come from the gate and not from a stored record.
    static let probeActionId = "5f0f0e00-0000-4000-8000-00000000e2e0"
    /// A well-formed 64-hex confirm token, so `action_execute` sees a request
    /// shape the module would accept if the gate were open.
    static let probeConfirmToken = String(repeating: "a", count: 64)

    static func run(_ h: Harness, capabilities: Capabilities) async throws {
        guard let session = h.session else {
            throw E2EFailure("the session was not established, so no action route can run")
        }
        guard let catalog = capabilities.actions else {
            throw E2EFailure("capabilities: the fixture published no action catalog")
        }

        try catalogChecks(h, catalog)

        let client = ActionClient(
            endpoint: h.endpoint,
            transport: h.transport,
            ownerToken: h.ownerToken,
            session: session
        )
        await client.updateCatalog(from: capabilities)
        try await clientChecks(h, client, catalog)

        if catalog.enabled {
            try await openGateFlow(h, client, catalog, session)
        } else {
            try await closedGateFlow(h, client, catalog, session)
        }

        try metaRouteChecks(h)
    }

    // MARK: - The catalog, whatever the gate says

    private static func catalogChecks(_ h: Harness, _ catalog: ActionCatalog) throws {
        try h.checks.expectEqual(catalog.schema, "e64local-api-v1", "actions: the catalog carries the schema marker")
        try h.checks.expectEqual(
            catalog.catalog.count, SimulatorFixture.catalogEntries,
            "actions: the catalog lists all 33 catalogue entries"
        )
        try h.checks.expectEqual(
            catalog.catalog.filter { $0.isImplemented }.count, SimulatorFixture.implementedEntries,
            "actions: 25 entries are implemented"
        )
        try h.checks.expectEqual(
            catalog.catalog.filter { !$0.isImplemented }.count, SimulatorFixture.unavailableEntries,
            "actions: 8 entries are unavailable"
        )
        try h.checks.expect(
            catalog.catalog.allSatisfy { !$0.evidence.isEmpty },
            "actions: every entry cites the evidence it was established from"
        )
        try h.checks.expect(
            catalog.catalog.filter { !$0.isImplemented }.allSatisfy { $0.reason != nil },
            "actions: every unavailable entry says why"
        )

        let destructive = catalog.catalog.filter { $0.destructive }
        try h.checks.expectEqual(
            destructive.count, SimulatorFixture.destructiveEntries,
            "actions: the catalog marks seven entries destructive"
        )
        try h.checks.expect(
            destructive.allSatisfy { $0.status == "implemented" },
            "actions: every destructive entry is implemented"
        )
        try h.checks.expect(
            destructive.allSatisfy { $0.blocked == SimulatorFixture.destructiveBlocked },
            "actions: each destructive entry reports the second gate as blocked"
        )
        try h.checks.expectEqual(
            catalog.catalog.filter { $0.risk == "destructive" }.count,
            SimulatorFixture.destructiveRiskClassEntries,
            "actions: eight entries are in the destructive risk class"
        )
        try h.checks.expect(
            destructive.allSatisfy { $0.risk == "destructive" },
            "actions: every entry the gate treats as destructive is in that class"
        )
        let factoryReset = catalog.entry("action_factory_reset")
        try h.checks.expect(
            factoryReset?.risk == "destructive"
                && factoryReset?.destructive == false
                && factoryReset?.isImplemented == false,
            "actions: the risk class and the gate's flag are distinct — factory_reset is classed destructive, not gated"
        )
        try h.checks.expectEqual(
            catalog.entry(SimulatorFixture.destructiveRoute)?.destructive, true,
            "actions: action_logs_clear is one of the destructive routes"
        )
        try h.checks.expectEqual(
            catalog.entry(SimulatorFixture.stopRoute)?.destructive, false,
            "actions: action_grind_stop is not destructive"
        )
        try h.checks.expect(
            !catalog.isDispatchable(SimulatorFixture.destructiveRoute),
            "actions: the catalog does not call a destructive route dispatchable while the second gate is off"
        )
    }

    // MARK: - The client's view of that catalog

    private static func clientChecks(
        _ h: Harness,
        _ client: ActionClient,
        _ catalog: ActionCatalog
    ) async throws {
        try h.checks.expect(await client.knownCatalog != nil, "action client: the catalog from capabilities was adopted")
        try h.checks.expectEqual(
            ActionClient.metaRoutes.count, 5,
            "action client: the five meta routes are the only action paths"
        )
        try h.checks.expectEqual(
            ActionClient.metaRoutes, SimulatorFixture.actionMetaRoutes,
            "action client: the meta routes are the documented five"
        )
        let dispatchable = await client.dispatchableRoutes()
        if catalog.enabled {
            let expected = Set(
                catalog.catalog.filter { $0.isImplemented && !$0.destructive }.map(\.route)
            )
            try h.checks.expectEqual(
                Set(dispatchable), expected,
                "action client: the dispatchable routes are exactly the implemented non-destructive ones"
            )
            try h.checks.expectEqual(
                dispatchable.count, SimulatorFixture.dispatchableWhenOpen,
                "action client: 18 routes are dispatchable with the destructive gate shut"
            )
            try h.checks.expect(
                !dispatchable.contains(SimulatorFixture.destructiveRoute),
                "action client: no destructive route is dispatchable"
            )
        } else {
            try h.checks.expect(
                dispatchable.isEmpty,
                "action client: nothing is dispatchable while the gate is closed"
            )
        }
        try h.checks.expect(await client.pendingActionIds().isEmpty, "action client: no confirm token is held before the first prepare")
        try h.checks.expectEqual(await client.retryAfterSeconds(), nil, "action client: no rate limit is pending")
    }

    // MARK: - Gate open: the real protocol

    private static func openGateFlow(
        _ h: Harness,
        _ client: ActionClient,
        _ catalog: ActionCatalog,
        _ session: VendorSession
    ) async throws {
        try h.checks.expectEqual(catalog.enabled, true, "actions: the first gate is open on this peer")
        try h.checks.expectEqual(catalog.destructiveEnabled, false, "actions: destructiveEnabled is false")
        try h.checks.expect(
            catalog.reason == nil,
            "actions: an open gate publishes no closed-gate reason"
        )
        try h.checks.expect(catalog.policy != nil, "actions: an open gate publishes its policy")
        let policy = catalog.policy
        try h.checks.expectEqual(policy?.version, 1, "actions: the policy is version 1")
        try h.checks.expectEqual(
            policy?.tokenTtlSec["actuator"], 60,
            "actions: an actuator's confirm token is good for 60 s"
        )
        try h.checks.expectEqual(
            policy?.tokenTtlSec["stateChanging"], 600,
            "actions: a state-changing confirm token is good for 600 s"
        )
        try h.checks.expectEqual(
            policy?.tokenTtlSec["destructive"], 60,
            "actions: a destructive confirm token is good for 60 s"
        )
        try h.checks.expectEqual(
            policy?.audit?.file, "/db/e64local/audit.jsonl",
            "actions: the policy names the audit file"
        )
        try h.checks.expectEqual(policy?.audit?.maxBytes, 1_048_576, "actions: the audit file is capped at 1 MiB")
        try h.checks.expectEqual(policy?.audit?.keep, 3, "actions: three audit files are kept")
        try h.checks.expectEqual(
            policy?.bounds["targetWeightGr"]?.min, 0.1,
            "actions: the effective lower bound for targetWeightGr is published"
        )
        try h.checks.expectEqual(
            policy?.bounds["targetWeightGr"]?.max, 50.0,
            "actions: the effective upper bound for targetWeightGr is published"
        )
        try h.checks.expectEqual(
            policy?.rateLimits["grind_start"],
            JSONField.object(["perMinute": .number(6), "perHour": .number(30)]),
            "actions: the grind-start rate bucket is published"
        )
        try h.checks.expectEqual(
            catalog.actionRoutes.count, SimulatorFixture.dispatchableWhenOpen,
            "actions: the gate advertises its 18 dispatchable routes"
        )
        try h.checks.expect(
            !catalog.actionRoutes.contains(SimulatorFixture.destructiveRoute),
            "actions: the destructive route stays out of the dispatchable list"
        )

        // MARK: prepare → execute → status → audit

        let prepared = try await client.prepare(route: SimulatorFixture.stopRoute)
        try h.checks.expectEqual(
            prepared.actionRoute, SimulatorFixture.stopRoute,
            "prepare: the record names the route that was prepared"
        )
        try h.checks.expectEqual(prepared.state, .prepared, "prepare: the record is in the prepared state")
        try h.checks.expect(
            ActionIdentifier.isValid(prepared.actionId),
            "prepare: the actionId is the UUID shape the client accepts"
        )
        try h.checks.expect(prepared.auditId != nil, "prepare: the record carries an auditId")
        try h.checks.expectEqual(prepared.idempotent, false, "prepare: a first prepare is not an idempotent replay")
        try h.checks.expect(!prepared.isExpired(), "prepare: the confirm token is still inside its TTL")
        try h.checks.expect(
            prepared.warnings.isEmpty,
            "prepare: the fixture reports no precondition warnings for a grind stop"
        )
        try h.checks.expect(
            !String(describing: prepared).lowercased().contains("token"),
            "prepare: the value handed back to the caller carries no confirm token"
        )
        try h.checks.expectEqual(
            await client.pendingActionIds(), [prepared.actionId],
            "prepare: exactly this action's confirm token is held"
        )

        let outcome = try await client.execute(prepared)
        try h.checks.expectEqual(outcome.actionId, prepared.actionId, "execute: the outcome names the action that ran")
        try h.checks.expectEqual(outcome.state, .completed, "execute: the action completed")
        try h.checks.expect(outcome.succeeded, "execute: the outcome reports success")
        try h.checks.expectEqual(
            outcome.result["command"], JSONField.string("Stop"),
            "execute: the device reported the Stop command"
        )
        try h.checks.expectEqual(outcome.auditId, prepared.auditId, "execute: the auditId is the one prepare returned")
        try h.checks.expect(outcome.durationMs != nil, "execute: the outcome carries a duration")
        try h.checks.expect(
            await client.pendingActionIds().isEmpty,
            "execute: the confirm token was spent, not kept"
        )

        let status = try await client.status(actionId: prepared.actionId)
        try h.checks.expectEqual(status.actionId, prepared.actionId, "status: the record is the one that ran")
        try h.checks.expectEqual(status.actionRoute, SimulatorFixture.stopRoute, "status: the record names the route")
        try h.checks.expectEqual(status.state, .completed, "status: the stored state is completed")
        try h.checks.expectEqual(status.errorCode, 0, "status: the record reports no error")
        try h.checks.expect(status.error == nil, "status: the record carries no error message")
        try h.checks.expect(
            status.preparedAt != nil && status.startedAt != nil && status.finishedAt != nil,
            "status: the record has prepared, started and finished timestamps"
        )
        try h.checks.expectEqual(status.cancelRequested, false, "status: no cancel was requested")
        try h.checks.expectEqual(
            status.result["command"], JSONField.string("Stop"),
            "status: the stored result is the device's own report"
        )

        let page = try await client.audit()
        try h.checks.expectEqual(page.route, "action_audit", "audit: the page names its route")
        try h.checks.expectEqual(page.limit, ActionAuditQuery.defaultLimit, "audit: the default page is 50 rows")
        try h.checks.expectEqual(page.offset, 0, "audit: the first page starts at offset 0")
        try h.checks.expectEqual(page.rows.count, page.count, "audit: the count matches the rows returned")
        try h.checks.expect(page.total >= page.count, "audit: the total is at least the page")
        try h.checks.expect(page.count >= 3, "audit: prepare, execute and result are all recorded")

        guard let resultRow = page.rows.first(where: {
            $0.phase == "result" && $0.actionId == prepared.actionId
        }) else {
            throw E2EFailure("audit: the executed action has no result row")
        }
        try h.checks.expectEqual(resultRow.route, SimulatorFixture.stopRoute, "audit: the row names the route")
        try h.checks.expectEqual(resultRow.result, "completed", "audit: the row records the completed state")
        try h.checks.expectEqual(resultRow.errorCode, 0, "audit: the row records no error")
        try h.checks.expect(resultRow.durationMs != nil, "audit: the row records how long it took")
        try h.checks.expectEqual(
            resultRow.paramsHash?.count, 64,
            "audit: the row carries the canonical parameter hash"
        )
        try h.checks.expectEqual(resultRow.client?.addr, "127.0.0.1", "audit: the row records the client address")
        try h.checks.expect(
            page.rows.contains {
                $0.phase == "prepare" && $0.actionId == prepared.actionId && $0.requestId != nil
            },
            "audit: the prepare row records the requestId the client sent"
        )

        let firstTwo = try await client.audit(query: try ActionAuditQuery(limit: 2))
        try h.checks.expectEqual(firstTwo.count, 2, "audit: a two-row page returns two rows")
        try h.checks.expectEqual(firstTwo.hasMore, true, "audit: a full page reports that more rows exist")
        try h.checks.expectEqual(firstTwo.nextOffset, 2, "audit: the next page's offset is offset + count")

        // MARK: cancel before execute

        let second = try await client.prepare(route: SimulatorFixture.cancelRoute)
        try h.checks.expectEqual(second.state, .prepared, "prepare: the second action is prepared, not executed")
        let cancelled = try await client.cancel(actionId: second.actionId)
        try h.checks.expectEqual(cancelled.actionId, second.actionId, "cancel: the reply names the action")
        try h.checks.expectEqual(cancelled.state, .cancelled, "cancel: a prepared action becomes cancelled")
        try h.checks.expectEqual(cancelled.cancelled, true, "cancel: the reply reports the cancellation")
        try h.checks.expectEqual(
            cancelled.stopSent, false,
            "cancel: nothing had started, so no stop primitive was sent"
        )
        try h.checks.expect(
            await client.pendingActionIds().isEmpty,
            "cancel: the held confirm token was dropped, so the action can never run"
        )
        do {
            _ = try await client.execute(actionId: second.actionId)
            throw E2EFailure("cancel: a cancelled action was executed")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .noPendingAction = error else {
                throw E2EFailure("cancel: expected .noPendingAction after the cancel, got \(error)")
            }
            try h.checks.expect(
                error.errorCode == nil,
                "cancel: executing a cancelled action is refused by the client, not by the device"
            )
        }

        let cancelledStatus = try await client.status(actionId: second.actionId)
        try h.checks.expectEqual(cancelledStatus.state, .cancelled, "cancel: the stored record is cancelled")
        try h.checks.expect(
            cancelledStatus.startedAt == nil,
            "cancel: the record never started"
        )
        try h.checks.expectEqual(
            cancelledStatus.cancelRequested, false,
            "cancel: a prepared action needs no interrupt, so no cancel was requested"
        )

        let afterCancel = try await client.audit(query: try ActionAuditQuery(limit: 10))
        try h.checks.expect(
            afterCancel.rows.contains {
                $0.phase == "cancel" && $0.actionId == second.actionId
                    && $0.result == "cancelled_before_execute"
            },
            "cancel: the audit trail records the cancellation as cancelled_before_execute"
        )

        // MARK: the destructive gate, with the second gate shut

        let beforeDestructive = h.transport.sentRequests().count
        do {
            _ = try await client.prepare(route: SimulatorFixture.destructiveRoute)
            throw E2EFailure("prepare: a destructive route was dispatched while the second gate was shut")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .destructiveGateClosed(let message) = error else {
                throw E2EFailure("prepare: expected .destructiveGateClosed, got \(error)")
            }
            try h.checks.expectEqual(
                message, SimulatorFixture.destructiveBlocked,
                "prepare: the refusal repeats the catalog's blocked text for the second gate"
            )
            try h.checks.expectEqual(error.errorCode, 403, "prepare: the destructive refusal is 403-shaped")
        }
        try h.checks.expectEqual(
            h.transport.sentRequests().count, beforeDestructive,
            "prepare: the destructive refusal is decided before a byte is sent"
        )

        // The fixture refuses it on the wire too, with the second gate's own
        // message rather than the closed first gate's.
        let rawDestructive = try await h.transport.post(
            "/rest_api/action_prepare",
            json: [
                "route": SimulatorFixture.destructiveRoute,
                "params": [String: Any](),
                "requestId": "e2e-destructive-0001",
            ],
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(
            rawDestructive.status, 403,
            "action_prepare: the fixture refuses a destructive route with HTTP 403"
        )
        try h.checks.expectEqual(
            rawDestructive.int("errorCode"), 403,
            "action_prepare: the body carries errorCode 403"
        )
        try h.checks.expectEqual(
            rawDestructive.string("error"), SimulatorFixture.destructiveBlocked,
            "action_prepare: the wire refusal is the second gate's message, not the first gate's"
        )
    }

    // MARK: - Gate closed: everything is refused, and nothing is sent blindly

    private static func closedGateFlow(
        _ h: Harness,
        _ client: ActionClient,
        _ catalog: ActionCatalog,
        _ session: VendorSession
    ) async throws {
        try h.checks.expectEqual(
            catalog.enabled, false,
            "actions: the first gate is closed because no policy file is installed"
        )
        try h.checks.expectEqual(catalog.destructiveEnabled, false, "actions: destructiveEnabled is false")
        try h.checks.expectEqual(
            catalog.reason, SimulatorFixture.gateReason,
            "actions: the catalog names the reason the gate is closed"
        )
        try h.checks.expect(
            catalog.actionRoutes.isEmpty,
            "actions: a closed gate advertises no dispatchable route"
        )
        try h.checks.expect(
            catalog.policy == nil,
            "actions: no policy document is published while the gate is closed"
        )

        // MARK: prepare — refused locally, and by the device

        let beforePrepare = h.transport.sentRequests().count
        do {
            _ = try await client.prepare(route: SimulatorFixture.stopRoute)
            throw E2EFailure("prepare: the client dispatched an action while the gate was closed")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .gateClosed(let message) = error else {
                throw E2EFailure("prepare: expected .gateClosed, got \(error)")
            }
            try h.checks.expectEqual(
                message, catalog.reason,
                "prepare: the refusal repeats the reason capabilities published"
            )
            try h.checks.expectEqual(error.errorCode, 403, "prepare: the refusal is 403-shaped")
        }
        try h.checks.expectEqual(
            h.transport.sentRequests().count, beforePrepare,
            "prepare: a closed gate costs no request"
        )

        do {
            _ = try await client.prepare(route: SimulatorFixture.destructiveRoute)
            throw E2EFailure("prepare: the client dispatched a destructive action while the gate was closed")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .gateClosed = error else {
                throw E2EFailure(
                    "prepare: the first gate must refuse a destructive route before the second is consulted, got \(error)"
                )
            }
            try h.checks.expectEqual(
                h.transport.sentRequests().count, beforePrepare,
                "prepare: the destructive attempt costs no request either"
            )
        }

        let rawPrepare = try await h.transport.post(
            "/rest_api/action_prepare",
            json: [
                "route": SimulatorFixture.stopRoute,
                "params": [String: Any](),
                "requestId": "e2e-prepare-0001",
            ],
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(rawPrepare.status, 403, "action_prepare: the fixture refuses the route over the wire")
        try h.checks.expectEqual(rawPrepare.int("errorCode"), 403, "action_prepare: the body carries errorCode 403")
        try h.checks.expectEqual(
            rawPrepare.string("error"), catalog.reason,
            "action_prepare: the wire refusal is the reason capabilities published"
        )
        try h.checks.expectEqual(rawPrepare.bool("success"), false, "action_prepare: the envelope is not a success")
        try h.checks.expectEqual(rawPrepare.bool("simulator"), true, "action_prepare: the refusal comes from the fixture")

        // MARK: execute — refused locally, and by the device

        do {
            _ = try await client.execute(actionId: probeActionId)
            throw E2EFailure("execute: the client executed an action it never prepared")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .noPendingAction = error else {
                throw E2EFailure("execute: expected .noPendingAction, got \(error)")
            }
            try h.checks.expect(
                error.errorCode == nil,
                "execute: a missing confirm token is refused here, with no device code"
            )
        }

        let rawExecute = try await h.transport.post(
            "/rest_api/action_execute",
            json: ["actionId": probeActionId, "confirmToken": probeConfirmToken],
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(rawExecute.status, 403, "action_execute: the fixture refuses execution over the wire")
        try h.checks.expectEqual(rawExecute.int("errorCode"), 403, "action_execute: the body carries errorCode 403")
        try h.checks.expectEqual(
            rawExecute.string("error"), catalog.reason,
            "action_execute: the wire refusal is the gate reason"
        )

        // MARK: status, cancel and audit — refused by the device

        do {
            _ = try await client.status(actionId: probeActionId)
            throw E2EFailure("status: the fixture answered a status read while the gate is closed")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .forbidden(let message) = error else {
                throw E2EFailure("status: expected .forbidden, got \(error)")
            }
            try h.checks.expectEqual(message, catalog.reason, "status: the refusal repeats the gate reason")
            try h.checks.expectEqual(error.errorCode, 403, "status: the refusal is 403-shaped")
        }

        do {
            _ = try await client.cancel(actionId: probeActionId)
            throw E2EFailure("cancel: the fixture cancelled while the gate is closed")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .forbidden(let message) = error else {
                throw E2EFailure("cancel: expected .forbidden, got \(error)")
            }
            try h.checks.expectEqual(
                message, catalog.reason,
                "cancel: the gate answers a cancel-before-execute with its own reason"
            )
            try h.checks.expectEqual(
                error.errorCode, 403,
                "cancel: the refusal is 403, not the 404 an unknown action id would give"
            )
            try h.checks.expect(
                await client.pendingActionIds().isEmpty,
                "cancel: nothing stays pending after a refused cancel"
            )
        }

        do {
            _ = try await client.audit(query: try ActionAuditQuery(limit: 10))
            throw E2EFailure("audit: the fixture answered the audit trail while the gate is closed")
        } catch let error as ActionError {
            h.note(error: error)
            guard case .forbidden(let message) = error else {
                throw E2EFailure("audit: expected .forbidden, got \(error)")
            }
            try h.checks.expectEqual(message, catalog.reason, "audit: the refusal repeats the gate reason")
            try h.checks.expectEqual(error.errorCode, 403, "audit: the refusal is 403-shaped")
        }
    }

    // MARK: - What went over the wire, either way

    private static func metaRouteChecks(_ h: Harness) throws {
        let actionRequests = h.transport.sentRequests().filter { request in
            guard let route = ReadSuite.routeOf(request) else { return false }
            return ActionClient.metaRoutes.contains(route)
        }
        let exercised = Set(actionRequests.compactMap { ReadSuite.routeOf($0) })
        try h.checks.expectEqual(
            exercised, ActionClient.metaRoutes,
            "actions: all five meta routes were exercised over the wire"
        )
        try h.checks.expect(
            actionRequests.allSatisfy { $0.header(LocalAPI.tokenHeader) == h.config.token },
            "actions: every action request carried the owner token header"
        )
        try h.checks.expect(
            actionRequests.allSatisfy { ($0.header("Cookie") ?? "").contains("PHPSESSID=") },
            "actions: every action request carried the vendor session cookie"
        )
    }
}
