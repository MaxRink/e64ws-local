import Foundation
import GrinderCore

/// Source-level checks for the action layer: the read shape the core did not
/// model, the module's route table, the classifier's wording and the promise
/// that no token or action state is written anywhere.
func actionSourceChecks() -> [CheckCase] {
    let coreRoot = repositoryRoot().appendingPathComponent("apps/ios/GrinderCore/Sources/GrinderCore")

    return [
        CheckCase("action: capabilities carries the catalog the core did not model") {
            let json = """
            {"data":{"schema":"e64local-api-v1","route":"capabilities","apiVersion":"1",
             "routes":["alert_log","capabilities","config","file","grind_log","machine","portafilters",
                       "recipes","service_log","settings","ws_token","action_prepare","action_execute",
                       "action_status","action_cancel","action_audit"],
             "actions":\(catalogDocument(enabled: true, destructiveEnabled: false)),
             "features":{"pagination":true,"timeFilters":true,"logRowTypes":"strings","recipeExport":"json",
                         "csvExport":false,"singleRecipe":false,"machineIdentity":"serial-sha256",
                         "wssToken":true,"actions":true,"destructiveActions":false},
             "limits":{"maxRows":5000,"defaultRows":{"grind_log":20},"maxOffset":1000000,
                       "maxFileBytes":1048576,"maxRequestBytes":16384},
             "serverTime":1767225600,"devMode":true},
             "success":true,"errorCode":0}
            """
            let transport = ActionTransport(["capabilities": jsonResponse(json)])
            let api = LocalAPI(
                endpoint: try Endpoint(host: "192.168.1.100"),
                transport: transport,
                ownerToken: OwnerToken.generate(),
                session: VendorSession(sessionID: "sess123")
            )
            let capabilities = try await api.capabilities()
            let catalog = try checkNotNil(capabilities.actions, "data.actions")
            try checkEqual(catalog.enabled, true)
            try checkEqual(catalog.destructiveEnabled, false)
            try checkEqual(catalog.actionRoutes, ["action_language_set"])
            try checkEqual(catalog.catalog.count, 3)
            try check(
                !catalog.isDispatchable("action_recipe_delete"),
                "a blocked destructive route is not dispatchable"
            )
            try check(
                catalog.isDispatchable("action_language_set"),
                "a dispatchable route is dispatchable"
            )
            let blocked = try checkNotNil(catalog.entry("action_recipe_delete")?.blocked, "blocked reason")
            try checkEqual(blocked, destructiveBlocked)
            try checkEqual(catalog.entry("action_grind_pause")?.status, "unavailable")
            let policy = try checkNotNil(catalog.policy, "policy")
            try checkEqual(policy.tokenTtlSec["actuator"], 60)
            try checkEqual(policy.tokenTtlSec["stateChanging"], 600)
            try checkEqual(policy.bounds["targetWeightGr"]?.max, 50)
            try checkEqual(policy.audit?.keep, 3)

            // The same catalog drives the action client, through the handshake
            // document rather than a hand-built catalog: this is the app's wiring.
            let client = try makeActionClient(ActionTransport())
            try checkEqual(await client.dispatchableRoutes(), [], "no catalog yet")
            await client.updateCatalog(from: capabilities)
            try checkEqual(await client.dispatchableRoutes(), ["action_language_set"])
        },

        CheckCase("action: a firmware without the action layer decodes as no catalog") {
            // The read route is optional: a module without the action layer
            // omits `actions`, and that must not make capabilities undecodable.
            let json = """
            {"data":{"schema":"e64local-api-v1","route":"capabilities","apiVersion":"1",
             "routes":["capabilities","machine"],
             "features":{"pagination":true,"timeFilters":true,"actions":false},
             "limits":{"maxRows":5000,"defaultRows":{},"maxOffset":1000000,
                       "maxFileBytes":1048576,"maxRequestBytes":16384},
             "devMode":true},"success":true,"errorCode":0}
            """
            let transport = ActionTransport(["capabilities": jsonResponse(json)])
            let api = LocalAPI(
                endpoint: try Endpoint(host: "192.168.1.100"),
                transport: transport,
                ownerToken: OwnerToken.generate()
            )
            let capabilities = try await api.capabilities()
            try checkNil(capabilities.actions, "data.actions")
            let client = try makeActionClient(ActionTransport())
            try checkEqual(await client.dispatchableRoutes(), [], "no catalog means nothing is dispatchable")
        },

        CheckCase("action: every route the module dispatches is modelled by one client") {
            let php = try sourceText(at: repositoryRoot().appendingPathComponent("ondevice/rest_api_dev.php"))
            guard let start = php.range(of: "switch ( $requestUri )") else {
                throw CheckFailure(message: "the dispatcher switch moved", file: #filePath, line: #line)
            }
            guard let end = php.range(of: "\n\t\t\tdefault:", range: start.upperBound..<php.endIndex) else {
                throw CheckFailure(message: "the dispatcher default case moved", file: #filePath, line: #line)
            }
            var dispatched: Set<String> = []
            for line in php[start.upperBound..<end.lowerBound].split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard trimmed.hasPrefix("case \""), trimmed.hasSuffix(":") else { continue }
                dispatched.insert(String(trimmed.dropFirst("case \"".count).dropLast(2)))
            }
            let modelled = LocalAPI.dataRoutes.union(ActionClient.metaRoutes).union(["ws_token"])
            try checkEqual(dispatched.count, 16, "the module's route table: \(dispatched.sorted())")
            try checkEqual(dispatched, modelled, "every dispatched route is modelled")
            try check(!ActionClient.metaRoutes.contains("ws_token"), "the action client never mints a WSS token")
            try check(!LocalAPI.dataRoutes.contains("ws_token"), "the read client never mints a WSS token")
            try checkEqual(
                ActionClient.metaRoutes,
                ["action_prepare", "action_execute", "action_status", "action_cancel", "action_audit"],
                "the five meta routes"
            )
        },

        CheckCase("action: the refusal classifier matches the module's own wording") {
            let php = try sourceText(at: repositoryRoot().appendingPathComponent("ondevice/rest_api_dev.php"))
            let swift = try sourceText(at: coreRoot.appendingPathComponent("Client/ActionClient.swift"))
            // The strings the classifier keys on must be the strings the module
            // sends.  A wording change in either fails this check instead of
            // silently reclassifying a refusal.
            for literal in [
                "the device has rebooted since this action was prepared",
                "the prepared action carries no boot id",
                "action is not in a state that allows execute",
                "destructive actions are disabled",
                "action unavailable: ",
                "rate limit exceeded",
                "the action is no longer available",
            ] {
                try check(php.contains(literal), "the module no longer sends: \(literal)")
            }
            try check(swift.contains("reboot"), "the classifier must key on the reboot wording")
            try check(swift.contains("boot id"), "the classifier must key on the boot-id wording")
            try check(
                swift.contains("destructive actions are disabled"),
                "the classifier must key on the destructive wording"
            )
            try check(
                swift.contains("action unavailable"),
                "the classifier must key on the unavailable wording"
            )
            for code in ["400", "401", "403", "404", "409", "422", "429", "503", "504"] {
                try check(swift.contains("case \(code)"), "the classifier must map \(code)")
            }
            // The 429 body key, not the HTTP status, is what the client reads.
            try check(swift.contains("retryAfter"), "the classifier must read retryAfter")
        },

        CheckCase("action: the action layer keeps nothing on disk and logs nothing") {
            let subjects = [
                (name: "Client/ActionClient.swift", text: try sourceText(
                    at: coreRoot.appendingPathComponent("Client/ActionClient.swift")
                )),
                (name: "Models/ActionModels.swift", text: try sourceText(
                    at: coreRoot.appendingPathComponent("Models/ActionModels.swift")
                )),
            ]
            for subject in subjects {
                for banned in [
                    "UserDefaults", "FileManager", "Keychain", "SecItem", ".write(to:",
                    "os_log", "NSLog",
                ] {
                    try check(
                        !subject.text.contains(banned),
                        "\(subject.name) must not reference \(banned)"
                    )
                }
                try check(loggingCall(in: subject.text) == nil, "\(subject.name) must not log")
            }
            // The token type is internal on purpose: app code cannot hold one.
            let client = subjects[0].text
            let models = subjects[1].text
            try check(client.contains("struct ConfirmToken"), "the token type must exist")
            try check(!client.contains("public struct ConfirmToken"), "the token type must not be public")
            try check(!client.contains("public let confirmToken"), "no public token accessor")
            try check(!models.contains("public let confirmToken"), "no public token accessor in the models")
            try check(client.contains("«confirm token withheld»"), "the token must be redacted")
            // The action identifier is a request value, never a path.
            try check(
                !client.contains("path: \"/rest_api/action_grind"),
                "an action identifier must never become a URL path"
            )
        },
    ]
}
