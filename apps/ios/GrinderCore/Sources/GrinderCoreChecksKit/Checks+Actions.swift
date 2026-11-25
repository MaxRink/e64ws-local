import Foundation
import GrinderCore

/// The action layer's behaviour: prepare, execute, status, cancel, audit, the
/// refusals that matter and the token's lifecycle.
///
/// The transport, catalog and JSON fixtures live in Checks+ActionFixtures.swift;
/// the source-level checks are in Checks+ActionsSource.swift.
func actionChecks() -> [CheckCase] {
    [
        CheckCase("action: the happy path is prepare, execute, status and audit") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(okEnvelope(executeJSON())),
                "action_status": jsonResponse(okEnvelope(statusJSON())),
                "action_audit": jsonResponse(okEnvelope(auditJSON(
                    rows: [auditRowJSON(phase: "prepare", result: "prepared")]
                ))),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())

            let prepared = try await client.prepare(
                route: "action_language_set",
                params: ["language": .string("de")],
                requestId: fixtureRequestId
            )
            try checkEqual(prepared.actionId, fixtureActionId)
            try checkEqual(prepared.actionRoute, "action_language_set")
            try checkEqual(prepared.state, .prepared)
            try checkEqual(prepared.warnings.count, 1, "warnings")

            let outcome = try await client.execute(actionId: prepared.actionId)
            try checkEqual(outcome.state, .completed)
            try check(outcome.succeeded, "the outcome must report success")
            try checkEqual(outcome.result["command"], .string("LanguageSet"))
            try checkEqual(outcome.durationMs, 912)

            let status = try await client.status(actionId: prepared.actionId)
            try checkEqual(status.state, .completed)
            try checkEqual(status.errorCode, 0)

            let page = try await client.audit()
            try checkEqual(page.rows.count, 1)
            try checkEqual(page.total, 7)
            try check(page.hasMore, "hasMore")
            try checkEqual(page.nextOffset, 1)

            try checkEqual(
                await transport.routeNames(),
                ["action_prepare", "action_execute", "action_status", "action_audit"],
                "route order"
            )
        },

        CheckCase("action: prepare sends the documented request shape") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let token = OwnerToken.generate()
            let client = try makeActionClient(transport, catalog: try fixtureCatalog(), token: token)
            _ = try await client.prepare(
                route: "action_language_set",
                params: ["language": .string("de"), "targetWeightGr": .number(18.0)],
                requestId: fixtureRequestId
            )
            let request = try checkNotNil(await transport.requests.first, "request")
            try checkEqual(request.method, "POST")
            try checkEqual(request.url.absoluteString, "https://192.168.1.100/rest_api/action_prepare")
            try checkEqual(request.headers["X-E64-Local-Token"], token.value)
            try checkEqual(request.headers["Cookie"], "PHPSESSID=sess123")
            try checkEqual(request.headers["Content-Type"], "application/json")

            let body = try decodeJSONObject(try checkNotNil(request.body, "body"))
            try checkEqual(body["route"] as? String, "action_language_set")
            try checkEqual(body["requestId"] as? String, fixtureRequestId)
            let params = try checkNotNil(body["params"] as? [String: Any], "params")
            try checkEqual(params["language"] as? String, "de")
            try checkEqual(params["targetWeightGr"] as? Double, 18.0)
            try checkEqual(params.count, 2, "the client sends exactly the parameters it was given")
            // The token is the device's answer, never something a prepare sends.
            try checkEqual(
                body["confirmToken"] as? String,
                nil,
                "prepare must not carry a confirm token"
            )
        },

        CheckCase("action: the prepared record the app sees holds no token") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                params: ["language": .string("de")],
                requestId: fixtureRequestId
            )
            try checkEqual(
                await client.pendingActionIds(),
                [fixtureActionId],
                "the token is held for this action"
            )
            let labels = Mirror(reflecting: prepared).children.compactMap(\.label)
            try check(!labels.contains("confirmToken"), "PreparedAction must not store a token: \(labels)")
            try check(!String(describing: prepared).contains(fixtureConfirmToken), "description leaks")
            try check(!String(reflecting: prepared).contains(fixtureConfirmToken), "debug description leaks")
        },

        CheckCase("action: execute sends the token once and then drops it") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(okEnvelope(executeJSON())),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                params: ["language": .string("de")],
                requestId: fixtureRequestId
            )
            _ = try await client.execute(actionId: prepared.actionId)

            let bodies = await transport.bodies()
            try checkEqual(bodies.count, 2, "one prepare and one execute")
            let object = try decodeJSONObject(Data(bodies[1].utf8))
            try checkEqual(object["actionId"] as? String, fixtureActionId)
            try checkEqual(object["confirmToken"] as? String, fixtureConfirmToken)
            try checkEqual(object.count, 2, "execute carries only actionId and confirmToken")
            try checkEqual(await client.pendingActionIds(), [], "a spent token is forgotten")
        },

        CheckCase("action: a second execute has no token to send") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(okEnvelope(executeJSON())),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            _ = try await client.execute(actionId: prepared.actionId)
            let error = try await expectRefusal("second execute") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .noPendingAction = error else {
                throw CheckFailure(
                    message: "expected noPendingAction, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(
                await transport.routeNames(),
                ["action_prepare", "action_execute"],
                "no second execute request"
            )
        },

        CheckCase("action: 401 is reported as the owner-token refusal") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(
                    refusalEnvelope(401, "Local API requires owner token in /db/e64local/token"),
                    status: 400
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("401") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .unauthorized = error else {
                throw CheckFailure(message: "expected unauthorized, got \(error)", file: #filePath, line: #line)
            }
            try check(error.userMessage.contains("owner token"), "the message must name the owner token")
            try checkEqual(error.errorCode, 401)
        },

        CheckCase("action: 403 is a closed gate, not a dev-mode problem") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(
                    refusalEnvelope(403, "actions are not enabled (policy file missing)")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("403") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .forbidden(let message) = error else {
                throw CheckFailure(message: "expected forbidden, got \(error)", file: #filePath, line: #line)
            }
            try check(message.contains("policy file missing"), "the device's reason is kept")
            try checkEqual(error.errorCode, 403)
        },

        CheckCase("action: a request without both factors never leaves the phone") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let noToken = ActionClient(
                endpoint: try Endpoint(host: "192.168.1.100"),
                transport: transport,
                session: VendorSession(sessionID: "sess123"),
                catalog: try fixtureCatalog()
            )
            let unauthorized = try await expectRefusal("no owner token") {
                _ = try await noToken.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .unauthorized = unauthorized else {
                throw CheckFailure(
                    message: "expected unauthorized, got \(unauthorized)",
                    file: #filePath,
                    line: #line
                )
            }

            let noSession = ActionClient(
                endpoint: try Endpoint(host: "192.168.1.100"),
                transport: transport,
                ownerToken: OwnerToken.generate(),
                catalog: try fixtureCatalog()
            )
            let forbidden = try await expectRefusal("no vendor session") {
                _ = try await noSession.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .forbidden = forbidden else {
                throw CheckFailure(message: "expected forbidden, got \(forbidden)", file: #filePath, line: #line)
            }
            try checkEqual(await transport.requests.count, 0, "nothing was sent")
        },

        CheckCase("action: 409 after a reboot is reported as rebooted and spends the token") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(
                    refusalEnvelope(409, "the device has rebooted since this action was prepared")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let error = try await expectRefusal("reboot") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .rebooted(let message) = error else {
                throw CheckFailure(message: "expected rebooted, got \(error)", file: #filePath, line: #line)
            }
            try check(message.contains("rebooted"), "the device's reason is kept")
            try check(error.isTerminal, "a reboot makes the token dead")
            try check(!error.isRetriable, "a reboot is not a retry")
            try checkEqual(await client.pendingActionIds(), [], "the token is dropped")
            try check(
                error.userMessage.contains("restarted"),
                "the owner is told the grinder restarted"
            )
        },

        CheckCase("action: 409 with no boot id is also the reboot binding") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(
                    refusalEnvelope(409, "the prepared action carries no boot id; refusing to execute it")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let error = try await expectRefusal("no boot id") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .rebooted = error else {
                throw CheckFailure(message: "expected rebooted, got \(error)", file: #filePath, line: #line)
            }
        },

        CheckCase("action: 409 replay is a state conflict, not a reboot") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(
                    refusalEnvelope(409, "action is not in a state that allows execute")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let error = try await expectRefusal("replay") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .conflict = error else {
                throw CheckFailure(message: "expected conflict, got \(error)", file: #filePath, line: #line)
            }
            try check(!error.isRetriable, "a replay must not be retried")
            try checkEqual(await client.pendingActionIds(), [], "a spent token is dropped")
        },

        CheckCase("action: 429 carries retryAfter and keeps the token") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(
                    refusalEnvelope(429, "rate limit exceeded", retryAfter: 12)
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let error = try await expectRefusal("429") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .rateLimited(let seconds) = error else {
                throw CheckFailure(message: "expected rateLimited, got \(error)", file: #filePath, line: #line)
            }
            try checkEqual(seconds, 12, "retryAfter comes from the body's top level")
            try check(error.isRetriable, "a 429 is retriable")
            try checkEqual(error.errorCode, 429)
            let remaining = try checkNotNil(await client.retryAfterSeconds(), "countdown")
            try check((10...12).contains(remaining), "the countdown started at 12 s, got \(remaining)")
            try checkEqual(
                await client.pendingActionIds(),
                [fixtureActionId],
                "the module refuses before claiming the record, so the token is kept"
            )
        },

        CheckCase("action: 503 keeps the token and says nothing ran") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(
                    refusalEnvelope(503, "rate-limit state is unavailable; refusing rather than exceeding the limit")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let error = try await expectRefusal("503") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .runnerUnavailable = error else {
                throw CheckFailure(
                    message: "expected runnerUnavailable, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try check(error.isRetriable, "503 is retriable")
            try checkEqual(await client.pendingActionIds(), [fixtureActionId], "the token is kept")
        },

        CheckCase("action: 422 unavailable names the missing capability") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(
                    refusalEnvelope(422, "action unavailable: the firmware has no pause command")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("unavailable") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .unavailable(let message) = error else {
                throw CheckFailure(message: "expected unavailable, got \(error)", file: #filePath, line: #line)
            }
            try check(message.contains("no pause command"), "the device's reason is kept")
            try checkEqual(error.errorCode, 422)
        },

        CheckCase("action: a catalog entry that is unavailable is refused before it is sent") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("catalog unavailable entry") {
                _ = try await client.prepare(route: "action_grind_pause", requestId: fixtureRequestId)
            }
            guard case .unavailable(let message) = error else {
                throw CheckFailure(message: "expected unavailable, got \(error)", file: #filePath, line: #line)
            }
            try check(message.contains("no pause command"), "the catalog's reason is kept")
            try checkEqual(await transport.requests.count, 0, "an unavailable action is never sent")
        },

        CheckCase("action: 422 for out-of-bounds parameters is not dispatched") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(
                    refusalEnvelope(422, "targetWeightGr must be between 0.1 and 50")
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("422 bounds") {
                _ = try await client.prepare(
                    route: "action_language_set",
                    params: ["targetWeightGr": .number(99.0)],
                    requestId: fixtureRequestId
                )
            }
            guard case .invalidParameters = error else {
                throw CheckFailure(
                    message: "expected invalidParameters, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(error.errorCode, 422)
        },

        CheckCase("action: cancel before execute is final") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_cancel": jsonResponse(
                    okEnvelope(cancelJSON(state: "cancelled", cancelled: true, stopSent: false))
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let cancel = try await client.cancel(actionId: prepared.actionId)
            try checkEqual(cancel.state, .cancelled)
            try check(cancel.cancelled, "a prepared action is cancelled outright")
            try check(!cancel.stopSent, "nothing was sent to the machine")
            try checkEqual(await client.pendingActionIds(), [], "a cancelled action can never execute")

            let error = try await expectRefusal("execute after cancel") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .noPendingAction = error else {
                throw CheckFailure(
                    message: "expected noPendingAction, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(
                await transport.routeNames(),
                ["action_prepare", "action_cancel"],
                "no execute was sent"
            )
        },

        CheckCase("action: cancel during execute sends the stop primitive") {
            let transport = GatedActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(okEnvelope(executeJSON(state: "cancelled"))),
                "action_cancel": jsonResponse(
                    okEnvelope(cancelJSON(
                        state: "cancelling",
                        cancelled: false,
                        stopSent: true,
                        note: "the stop primitive was sent"
                    ))
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )

            let running = Task { try await client.execute(actionId: prepared.actionId) }
            var waited = 0
            while await !transport.isExecuteWaiting(), waited < 2_000 {
                try await Task.sleep(nanoseconds: 2_000_000)
                waited += 1
            }
            try check(await transport.isExecuteWaiting(), "the execute request must be in flight")

            let cancel = try await client.cancel(actionId: prepared.actionId)
            try checkEqual(cancel.state, .cancelling)
            try check(!cancel.cancelled, "a running action cannot be cancelled outright")
            try check(cancel.stopSent, "the stop primitive was sent")

            await transport.openGate()
            let outcome = try await running.value
            // The module maps a completed run with a pending cancel to cancelled.
            try checkEqual(outcome.state, .cancelled)
            try checkEqual(await client.pendingActionIds(), [], "an interrupted action holds no token")
        },

        CheckCase("action: cancel of a terminal action is idempotent") {
            let transport = ActionTransport([
                "action_cancel": jsonResponse(
                    okEnvelope(cancelJSON(
                        state: "completed",
                        cancelled: false,
                        stopSent: false,
                        note: "the action is already in a terminal state"
                    ))
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let cancel = try await client.cancel(actionId: fixtureActionId)
            try checkEqual(cancel.state, .completed)
            try check(!cancel.cancelled, "a completed action is not cancelled")
            try checkEqual(cancel.note, "the action is already in a terminal state")
        },

        CheckCase("action: execute refuses when the gate closed after prepare") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(okEnvelope(executeJSON())),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            // The owner removed /db/e64local/actions.json between the two steps.
            await client.updateCatalog(try fixtureCatalog(enabled: false))
            let error = try await expectRefusal("gate closed after prepare") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .notDispatchable = error else {
                throw CheckFailure(
                    message: "expected notDispatchable, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(await transport.routeNames(), ["action_prepare"], "no execute was sent")
        },

        CheckCase("action: a route the catalog does not list as dispatchable is refused before it is sent") {
            // The gate is open and the entry is implemented, but `actionRoutes`
            // does not list it: the device's own answer to "would this run" wins.
            let strict = catalogDocument().replacingOccurrences(
                of: "\"actionRoutes\":[\"action_language_set\"]",
                with: "\"actionRoutes\":[]"
            )
            let catalog = try JSONDecoder().decode(ActionCatalog.self, from: Data(strict.utf8))
            try checkEqual(catalog.enabled, true)
            try checkEqual(catalog.actionRoutes, [], "the fixture must list no route")
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: catalog)
            let error = try await expectRefusal("not dispatchable") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .notDispatchable = error else {
                throw CheckFailure(
                    message: "expected notDispatchable, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(await transport.requests.count, 0, "nothing was sent")
        },

        CheckCase("action: the destructive gate refuses a destructive route before it is sent") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog(destructiveEnabled: false))
            let error = try await expectRefusal("destructive gate off") {
                _ = try await client.prepare(route: "action_recipe_delete", requestId: fixtureRequestId)
            }
            guard case .destructiveGateClosed(let message) = error else {
                throw CheckFailure(
                    message: "expected destructiveGateClosed, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(message, destructiveBlocked)
            try checkEqual(error.errorCode, 403)
            try checkEqual(await transport.requests.count, 0, "nothing was sent")
        },

        CheckCase("action: the destructive gate admits a destructive route only when it is enabled") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON(route: "action_recipe_delete"))),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog(destructiveEnabled: true))
            _ = try await client.prepare(route: "action_recipe_delete", requestId: fixtureRequestId)
            let body = try decodeJSONObject(Data(try checkNotNil(await transport.bodies().first, "body").utf8))
            try checkEqual(body["route"] as? String, "action_recipe_delete")
        },

        CheckCase("action: execute re-checks the destructive gate") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON(route: "action_recipe_delete"))),
                "action_execute": jsonResponse(okEnvelope(executeJSON())),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog(destructiveEnabled: true))
            let prepared = try await client.prepare(
                route: "action_recipe_delete",
                requestId: fixtureRequestId
            )
            // The owner turns the second gate off between prepare and execute.
            await client.updateCatalog(try fixtureCatalog(destructiveEnabled: false))
            let error = try await expectRefusal("gate closed after prepare") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .destructiveGateClosed = error else {
                throw CheckFailure(
                    message: "expected destructiveGateClosed, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(await transport.routeNames(), ["action_prepare"], "no execute was sent")
            try checkEqual(await client.pendingActionIds(), [], "the token is not kept for a closed gate")
        },

        CheckCase("action: prepare refuses without a catalog") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport)
            let error = try await expectRefusal("no catalog") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .catalogUnavailable = error else {
                throw CheckFailure(
                    message: "expected catalogUnavailable, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(await transport.requests.count, 0, "nothing was sent")
            try check(error.userMessage.contains("capabilities"), "the owner is told what is missing")
        },

        CheckCase("action: prepare refuses a route the catalog does not know") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("unknown route") {
                _ = try await client.prepare(route: "action_esp_flash", requestId: fixtureRequestId)
            }
            guard case .unknownRoute = error else {
                throw CheckFailure(message: "expected unknownRoute, got \(error)", file: #filePath, line: #line)
            }
        },

        CheckCase("action: a catalog with the first gate closed is refused before it is sent") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog(enabled: false))
            let error = try await expectRefusal("gate closed") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .gateClosed(let reason) = error else {
                throw CheckFailure(message: "expected gateClosed, got \(error)", file: #filePath, line: #line)
            }
            try check(reason.contains("policy file missing"), "the catalog's reason is kept")
            try checkEqual(await transport.requests.count, 0, "nothing was sent")
        },

        CheckCase("action: status decodes the stored record") {
            let transport = ActionTransport([
                "action_status": jsonResponse(okEnvelope(statusJSON(
                    state: "failed",
                    errorCode: 500,
                    error: "the runner exited 1",
                    cancelRequested: true
                ))),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let status = try await client.status(actionId: fixtureActionId)
            try checkEqual(status.actionId, fixtureActionId)
            try checkEqual(status.actionRoute, "action_language_set")
            try checkEqual(status.state, .failed)
            try checkEqual(status.errorCode, 500)
            try checkEqual(status.error, "the runner exited 1")
            try check(status.cancelRequested, "cancelRequested")
            try checkEqual(status.durationMs, 912)
            try checkEqual(status.result["command"], .string("LanguageSet"))
            try check(status.state.isTerminal, "a failed record is terminal")
        },

        CheckCase("action: audit decodes rows that carry no parameter value") {
            let rows = [
                auditRowJSON(phase: "prepare", result: "prepared"),
                auditRowJSON(phase: "result", result: "completed"),
            ]
            let transport = ActionTransport([
                "action_audit": jsonResponse(okEnvelope(auditJSON(rows: rows))),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let page = try await client.audit(query: try ActionAuditQuery(limit: 50))
            try checkEqual(page.route, "action_audit")
            try checkEqual(page.rows.count, 2)
            try checkEqual(page.total, 7)
            try checkEqual(page.nextOffset, 2)
            try check(page.hasMore, "hasMore")
            let first = try checkNotNil(page.rows.first, "row")
            try checkEqual(first.phase, "prepare")
            try checkEqual(first.paramsHash?.count, 64, "only the canonical hash is stored")
            try checkEqual(first.client?.addr, "192.168.1.20")
            // A row has no field that could hold a parameter value.
            let labels = Set(Mirror(reflecting: first).children.compactMap(\.label))
            try check(!labels.contains("params"), "rows must not carry parameters: \(labels.sorted())")
            try check(!labels.contains("confirmToken"), "rows must not carry a token")
        },

        CheckCase("action: the audit page size is clamped to the audit cap") {
            try checkEqual(try ActionAuditQuery().limit, 50, "default")
            try checkEqual(
                try ActionAuditQuery(limit: 5000).limit,
                1000,
                "clamped to 1000, not the log cap of 5000"
            )
            var threw = false
            do {
                _ = try ActionAuditQuery(limit: 10, since: "2026-01-02", until: "2026-01-01")
            } catch {
                threw = true
            }
            try check(threw, "since after until must be refused, as the module refuses it")
        },

        CheckCase("action: the body errorCode decides, not the HTTP status") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(
                    refusalEnvelope(429, "rate limit exceeded", retryAfter: 3),
                    status: 400
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("429 over HTTP 400") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .rateLimited(let seconds) = error else {
                throw CheckFailure(message: "expected rateLimited, got \(error)", file: #filePath, line: #line)
            }
            try checkEqual(seconds, 3, "the wait is read from the body")
        },

        CheckCase("action: an unreadable body is an unexpected response, not a crash") {
            let transport = ActionTransport([
                "action_prepare": TransportResponse(
                    status: 200,
                    headers: [:],
                    setCookieHeaders: [],
                    body: Data("not json at all".utf8)
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("garbage body") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .unexpectedResponse = error else {
                throw CheckFailure(
                    message: "expected unexpectedResponse, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
        },

        CheckCase("action: an empty body is an unexpected response") {
            let transport = ActionTransport([
                "action_prepare": TransportResponse(status: 200, headers: [:], setCookieHeaders: [], body: Data()),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("empty body") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .unexpectedResponse = error else {
                throw CheckFailure(
                    message: "expected unexpectedResponse, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
        },

        CheckCase("action: a malformed prepare answer is refused, not stored") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON(token: "not-a-real-token"))),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let error = try await expectRefusal("malformed token") {
                _ = try await client.prepare(route: "action_language_set", requestId: fixtureRequestId)
            }
            guard case .unexpectedResponse = error else {
                throw CheckFailure(
                    message: "expected unexpectedResponse, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(await client.pendingActionIds(), [], "nothing is held")
        },

        CheckCase("action: a failed execute is started-and-failed, not refused") {
            let transport = ActionTransport([
                "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                "action_execute": jsonResponse(
                    refusalEnvelope(
                        500,
                        "the runner exited 1",
                        data: "{\"actionId\":\"\(fixtureActionId)\","
                            + "\"actionRoute\":\"action_language_set\","
                            + "\"state\":\"failed\",\"auditId\":\"\(fixtureActionId)\","
                            + "\"result\":{},\"durationMs\":420}"
                    )
                ),
            ])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())
            let prepared = try await client.prepare(
                route: "action_language_set",
                requestId: fixtureRequestId
            )
            let error = try await expectRefusal("failed execute") {
                _ = try await client.execute(actionId: prepared.actionId)
            }
            guard case .executionFailed(let outcome, let code, let message) = error else {
                throw CheckFailure(
                    message: "expected executionFailed, got \(error)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(code, 500, "the device's code is kept")
            try checkEqual(outcome.state, .failed)
            try checkEqual(outcome.durationMs, 420)
            try checkEqual(message, "the runner exited 1")
            try check(error.isTerminal, "a failed action is terminal")
        },

        CheckCase("action: requestId and actionId are validated before sending") {
            let transport = ActionTransport(["action_prepare": jsonResponse(okEnvelope(prepareJSON()))])
            let client = try makeActionClient(transport, catalog: try fixtureCatalog())

            let badId = try await expectRefusal("short requestId") {
                _ = try await client.prepare(route: "action_language_set", requestId: "short")
            }
            guard case .invalidRequestId = badId else {
                throw CheckFailure(
                    message: "expected invalidRequestId, got \(badId)",
                    file: #filePath,
                    line: #line
                )
            }
            let spacey = try await expectRefusal("space in requestId") {
                _ = try await client.prepare(route: "action_language_set", requestId: "has a space here")
            }
            guard case .invalidRequestId = spacey else {
                throw CheckFailure(
                    message: "expected invalidRequestId, got \(spacey)",
                    file: #filePath,
                    line: #line
                )
            }
            let badAction = try await expectRefusal("bad actionId") {
                _ = try await client.status(actionId: "not-an-action-id")
            }
            guard case .invalidActionId = badAction else {
                throw CheckFailure(
                    message: "expected invalidActionId, got \(badAction)",
                    file: #filePath,
                    line: #line
                )
            }
            try checkEqual(await transport.requests.count, 0, "nothing was sent")

            try check(ActionRequestId.isValid(ActionRequestId.make()), "a generated requestId is valid")
            try checkEqual(ActionRequestId.make().count, 36)
            try check(ActionRequestId.isValid("a1234567"), "8 characters is the minimum")
            try check(!ActionRequestId.isValid("a123456"), "7 characters is too short")
            try check(!ActionRequestId.isValid(".abcdefgh"), "the first character must be alphanumeric")
            try check(ActionIdentifier.isValid(fixtureActionId), "the fixture id is valid")
            try check(
                !ActionIdentifier.isValid("0D6F7E8A-1B2C-4D3E-8F90-1A2B3C4D5E6F"),
                "the module accepts lowercase only"
            )
        },

        CheckCase("action: the confirm token never appears in a description or an error") {
            let failures: [(String, String)] = [
                ("400", refusalEnvelope(400, "confirmToken is required")),
                ("401", refusalEnvelope(401, "Local API requires owner token")),
                ("403", refusalEnvelope(403, "confirm token does not match this action")),
                ("404", refusalEnvelope(404, "unknown actionId")),
                ("409 reboot", refusalEnvelope(409, "the device has rebooted since this action was prepared")),
                ("409 replay", refusalEnvelope(409, "action is not in a state that allows execute")),
                ("422", refusalEnvelope(422, "targetWeightGr must be between 0.1 and 50")),
                ("429", refusalEnvelope(429, "rate limit exceeded", retryAfter: 5)),
                ("500", refusalEnvelope(500, "the runner exited 1")),
                ("503", refusalEnvelope(503, "the action runner is unavailable")),
                ("504", refusalEnvelope(504, "the action timed out")),
                ("999", refusalEnvelope(999, "something new")),
            ]
            var tokenBodies = 0
            for (label, body) in failures {
                let transport = ActionTransport([
                    "action_prepare": jsonResponse(okEnvelope(prepareJSON())),
                    "action_execute": jsonResponse(body),
                ])
                let client = try makeActionClient(transport, catalog: try fixtureCatalog())
                let prepared = try await client.prepare(
                    route: "action_language_set",
                    requestId: fixtureRequestId
                )
                try check(
                    !String(describing: prepared).contains(fixtureConfirmToken),
                    "\(label): the prepared record must not render the token"
                )
                let error = try await expectRefusal(label) {
                    _ = try await client.execute(actionId: prepared.actionId)
                }
                let rendered = [
                    String(describing: error),
                    String(reflecting: error),
                    error.userMessage,
                    (error as LocalizedError).errorDescription ?? "",
                ].joined(separator: "\n")
                try check(
                    !rendered.contains(fixtureConfirmToken),
                    "\(label): the refusal must not render the token"
                )
                // The token is sent once, in the execute body, and nowhere else.
                let routes = await transport.routeNames()
                let bodies = await transport.bodies()
                for (index, text) in bodies.enumerated() {
                    if text.contains(fixtureConfirmToken) { tokenBodies += 1 }
                    if routes[index] != "action_execute" {
                        try check(
                            !text.contains(fixtureConfirmToken),
                            "\(label): \(routes[index]) must not carry the token"
                        )
                    }
                }
            }
            try checkEqual(tokenBodies, failures.count, "the token is sent exactly once per execute")
        },
    ]
}
