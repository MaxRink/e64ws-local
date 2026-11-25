import Foundation
import GrinderCore

/// The ten read routes the shipped `LocalAPI` client calls, over a real
/// `URLSession`, decoded by the shipped models.
///
/// The checks are about the HTTP half the offline suite stubs out: the envelope,
/// the `limit`/`offset`/`since` normalisation, string-typed DB rows, the
/// redaction predicate, and the two factors on every request.
enum ReadSuite {
    static func run(_ h: Harness) async throws -> Capabilities {
        guard let session = h.session else {
            throw E2EFailure("the session was not established, so no read can run")
        }
        let api = h.localAPI(token: h.ownerToken, session: session)

        // MARK: capabilities — the handshake

        let capabilities = try await api.capabilities()
        try h.checks.expectEqual(capabilities.apiVersion, "1", "capabilities: apiVersion is 1")
        // An open action gate adds its five meta routes to the list, so the
        // expectation is the read routes plus whatever the catalog says the gate
        // lets through — not a hard-coded eleven.
        let gateOpen = capabilities.actions?.enabled == true
        let expectedRoutes = SimulatorFixture.readRoutes
            .union(gateOpen ? SimulatorFixture.actionMetaRoutes : [])
        try h.checks.expectEqual(
            Set(capabilities.routes), expectedRoutes,
            "capabilities: the routes are the eleven reads plus the five meta routes when the gate is open"
        )
        try h.checks.expect(
            Set(LocalAPI.dataRoutes).isSubset(of: Set(capabilities.routes)),
            "capabilities: every route the read client calls is offered"
        )
        try h.checks.expectEqual(
            LocalAPI.dataRoutes.count, 10,
            "capabilities: the read client calls ten routes"
        )
        try h.checks.expect(
            !LocalAPI.dataRoutes.contains("ws_token"),
            "capabilities: the read client never calls ws_token"
        )
        try h.checks.expectEqual(
            capabilities.features.actions, gateOpen,
            "capabilities: features.actions agrees with the catalog's own gate flag"
        )
        try h.checks.expectEqual(
            capabilities.features.pagination, true,
            "capabilities: pagination is advertised"
        )
        try h.checks.expectEqual(
            capabilities.features.timeFilters, true,
            "capabilities: time filters are advertised"
        )
        try h.checks.expectEqual(
            capabilities.features.logRowTypes, "strings",
            "capabilities: log rows are advertised as strings"
        )
        try h.checks.expectEqual(
            capabilities.features.machineIdentity, "serial-sha256",
            "capabilities: the machine identity is the hashed serial"
        )
        try h.checks.expectEqual(capabilities.devMode, true, "capabilities: the fixture is a dev-mode peer")
        try h.checks.expect(capabilities.serverTime != nil, "capabilities: the fixture reports its clock")
        try h.checks.expectEqual(capabilities.limits.maxRows, 5_000, "capabilities: the row cap is 5000")
        try h.checks.expectEqual(
            capabilities.limits.defaultRows["grind_log"], 20,
            "capabilities: the grind log defaults to 20 rows"
        )
        try h.checks.expectEqual(
            capabilities.limits.defaultRows["service_log"], 500,
            "capabilities: the service log defaults to 500 rows"
        )
        try h.checks.expectEqual(capabilities.limits.maxOffset, 1_000_000, "capabilities: the offset cap is 1000000")
        try h.checks.expectEqual(
            capabilities.limits.maxFileBytes, 1_048_576,
            "capabilities: the file cap is 1 MiB"
        )
        try h.checks.expectEqual(
            capabilities.limits.maxRequestBytes, 16_384,
            "capabilities: the request cap is 16 KiB"
        )

        // MARK: machine

        let machine = try await api.machine()
        try h.checks.expectEqual(machine.variant, SimulatorFixture.variant, "machine: the variant is read")
        try h.checks.expectEqual(machine.model, SimulatorFixture.model, "machine: the model is read")
        try h.checks.expectEqual(machine.grinderType, 5, "machine: the grinder type id is read")
        try h.checks.expectEqual(
            machine.grinderTypeName, SimulatorFixture.model,
            "machine: the grinder type name is read"
        )
        try h.checks.expectEqual(machine.firmware, SimulatorFixture.firmware, "machine: the firmware build is read")
        try h.checks.expectEqual(machine.devMode, true, "machine: the dev-mode flag is read")
        try h.checks.expectEqual(machine.serialPresent, true, "machine: the fixture has a serial")
        try h.checks.expectEqual(
            machine.serialSha256,
            Fingerprints.sha256Hex(Data(SimulatorFixture.serialNumber.utf8)),
            "machine: the serial is only ever returned as its SHA-256"
        )
        try h.checks.expect(
            machine.serialNote.contains("never returned"),
            "machine: the document says the raw serial is withheld"
        )

        // MARK: grind_log

        let grinds = try await api.log(.grind)
        try h.checks.expectEqual(grinds.route, "grind_log", "grind_log: the page names its route")
        try h.checks.expectEqual(
            grinds.limit, LogKind.grind.defaultLimit,
            "grind_log: the client sends the route's own default limit"
        )
        try h.checks.expectEqual(grinds.offset, 0, "grind_log: the first page starts at offset 0")
        try h.checks.expectEqual(
            grinds.rows.count, grinds.count,
            "grind_log: the count matches the rows returned"
        )
        try h.checks.expectEqual(
            grinds.hasMore, grinds.count == grinds.limit,
            "grind_log: hasMore follows the fixture's page rule"
        )
        try h.checks.expectEqual(grinds.nextOffset, grinds.count, "grind_log: the next page's offset is offset + count")

        let filtered = try await api.log(
            .grind,
            query: try LogQuery(limit: 5, since: "2026-01-01")
        )
        try h.checks.expectEqual(
            filtered.since, "2026-01-01 00:00:00",
            "grind_log: a date-only since filter is normalised by the fixture"
        )
        try h.checks.expectEqual(filtered.limit, 5, "grind_log: the requested limit is echoed back")

        let clamped = try await api.log(.grind, query: try LogQuery(limit: 99_999))
        try h.checks.expectEqual(
            clamped.limit, LogQuery.maxLimit,
            "grind_log: a limit above the cap is clamped to the documented maximum"
        )

        // MARK: service_log

        let service = try await api.log(.service)
        try h.checks.expectEqual(service.route, "service_log", "service_log: the page names its route")
        try h.checks.expect(
            service.count >= 3,
            "service_log: the fixture seeds at least three rows"
        )
        try h.checks.expect(
            service.rows.contains { $0["event_type"] == "PowerOn" },
            "service_log: the seeded PowerOn row is readable"
        )
        try h.checks.expect(
            service.rows.contains {
                $0["event_type"] == "LogIn"
                    && ($0["event_details"] ?? "").contains("Role Owner logged in")
            },
            "service_log: this session's login was logged by the fixture"
        )
        guard let wifiDetails = service.rows
            .first(where: { $0["event_type"] == "WifiConnected" })?["event_details"]
        else {
            throw E2EFailure("service_log: the fixture did not seed a WifiConnected row")
        }
        try h.checks.expect(
            !wifiDetails.contains(SimulatorFixture.wifiSecret),
            "service_log: the row's WPA password was redacted"
        )
        try h.checks.expect(
            !wifiDetails.contains(SimulatorFixture.wifiAddress),
            "service_log: the row's IP address was redacted"
        )
        try h.checks.expect(
            wifiDetails.contains("<redacted>"),
            "service_log: the redaction is visible in the row text"
        )

        let paged = try await api.log(.service, query: try LogQuery(limit: 1, offset: 1))
        try h.checks.expectEqual(paged.count, 1, "service_log: a one-row page returns one row")
        try h.checks.expectEqual(paged.offset, 1, "service_log: the offset is echoed back")
        try h.checks.expectEqual(paged.hasMore, true, "service_log: a full page reports that more rows exist")

        // MARK: alert_log

        let alerts = try await api.log(.alert)
        try h.checks.expectEqual(alerts.route, "alert_log", "alert_log: the page names its route")
        try h.checks.expectEqual(alerts.count, 1, "alert_log: the fixture seeds one alert")
        try h.checks.expectEqual(
            alerts.rows.first?["alert_type"], "WaterEmpty",
            "alert_log: the alert type is readable"
        )
        try h.checks.expectEqual(
            alerts.rows.first?["alert_active"], "0",
            "alert_log: a database-backed flag arrives as a string"
        )

        // MARK: portafilters and recipes

        let portafilters = try await api.portafilters()
        try h.checks.expectEqual(portafilters.route, "portafilters", "portafilters: the table names its route")
        try h.checks.expectEqual(portafilters.count, 1, "portafilters: the fixture seeds one row")
        try h.checks.expectEqual(
            portafilters.rows.first?["weight_tolerance"], "5",
            "portafilters: the tolerance is a string"
        )

        let recipes = try await api.recipes()
        try h.checks.expectEqual(recipes.route, "recipes", "recipes: the table names its route")
        try h.checks.expectEqual(recipes.count, 1, "recipes: the fixture seeds one recipe")
        try h.checks.expectEqual(
            recipes.rows.first?["recipe_mode"], "GbW",
            "recipes: the mode is readable"
        )
        try h.checks.expectEqual(
            recipes.rows.first?["recipe_amount"], "18000",
            "recipes: the amount keeps the vendor's integer encoding"
        )
        try h.checks.expectEqual(
            recipes.rows.first?["recipe_uuid"]?.count, 36,
            "recipes: the UUID is readable"
        )

        // MARK: settings

        let settings = try await api.settings()
        try h.checks.expectEqual(settings.route, "settings", "settings: the export names its route")
        try h.checks.expectEqual(
            settings.count, settings.settings.count,
            "settings: the count matches the keys kept"
        )
        try h.checks.expectEqual(
            Set(settings.redacted), SimulatorFixture.redactedSettingKeys,
            "settings: exactly the six sensitive keys are withheld"
        )
        try h.checks.expect(
            settings.settings.keys.allSatisfy { !looksSensitive($0) },
            "settings: no key the fixture withheld survived into the map"
        )
        try h.checks.expectEqual(
            settings.settings["System.Language"], "en_US",
            "settings: a non-sensitive value is readable"
        )

        // MARK: config

        let config = try await api.config()
        try h.checks.expectEqual(config.route, "config", "config: the export names its route")
        try h.checks.expectEqual(
            config.config["productionWifiPassword"], JSONField.string("<redacted>"),
            "config: the WiFi password is replaced, not omitted"
        )
        try h.checks.expectEqual(
            config.config["productionWifiSsid"], JSONField.string("<redacted>"),
            "config: the production SSID is replaced"
        )
        try h.checks.expectEqual(
            config.config["grinderSn"], JSONField.string("<redacted>"),
            "config: the serial number is replaced"
        )
        try h.checks.expectEqual(
            config.config["cloudBaseUrl"], JSONField.string("<redacted>"),
            "config: the cloud URL is replaced"
        )
        try h.checks.expectEqual(
            config.config["targetWeightGr"], JSONField.number(18.0),
            "config: an ordinary numeric value survives the redaction pass"
        )
        try h.checks.expectEqual(
            config.config["_e64local_schema"], JSONField.string("e64local-api-v1"),
            "config: the fixture stamps its schema marker after redacting"
        )
        try h.checks.expectEqual(
            Set(config.redacted), SimulatorFixture.redactedConfigPaths,
            "config: the redacted path list names all four fields"
        )

        // MARK: file

        let issue = try await api.file(path: "/etc/issue")
        try h.checks.expectEqual(issue.path, "/etc/issue", "file: the reply names the path it read")
        try h.checks.expectEqual(issue.encoding, FileContent.Encoding.text, "file: an allowlisted file is text")
        try h.checks.expect(
            issue.content.contains("HEM-HSG.140"),
            "file: /etc/issue is the development image string"
        )
        try h.checks.expectEqual(
            issue.byteCount, issue.content.utf8.count,
            "file: the byte count matches the content"
        )

        let logFile = try await api.file(path: "/log/messages")
        try h.checks.expect(
            logFile.content.contains("<redacted>"),
            "file: /log text is passed through the redactor"
        )
        try h.checks.expect(
            !logFile.content.contains(SimulatorFixture.logSecret),
            "file: the seeded password never leaves the fixture"
        )

        let beforeRefusal = h.transport.sentRequests().count
        do {
            _ = try await api.file(path: "/etc/passwd")
            throw E2EFailure("file: a path outside the allowlist was read")
        } catch let error as LocalAPIError {
            h.note(error: error)
            try h.checks.expectEqual(
                error.code, 400,
                "file: a path outside the allowlist is refused with the client's 400"
            )
        }
        try h.checks.expectEqual(
            h.transport.sentRequests().count, beforeRefusal,
            "file: the allowlist refusal costs no request"
        )

        // MARK: both factors on the wire

        let readRequests = h.transport.sentRequests().filter { request in
            guard let route = routeOf(request) else { return false }
            return LocalAPI.dataRoutes.contains(route)
        }
        try h.checks.expect(
            readRequests.count >= 10,
            "auth: the suite sent at least ten read-route requests"
        )
        try h.checks.expect(
            readRequests.allSatisfy { $0.header(LocalAPI.tokenHeader) == h.config.token },
            "auth: every read request carried the owner token in its header"
        )
        try h.checks.expect(
            readRequests.allSatisfy { ($0.header("Cookie") ?? "").contains("PHPSESSID=") },
            "auth: every read request carried the vendor session cookie"
        )
        try h.checks.expect(
            !h.usesStandInOwnerToken,
            "auth: the client holds the fixture token itself, not a stand-in"
        )
        try h.checks.expect(
            h.config.token.count == 64 && h.config.token.allSatisfy(\.isHexDigit),
            "auth: the fixture token is the 64-hex shape a device writes"
        )

        return capabilities
    }

    /// The route name from a `/rest_api/<route>` path.
    static func routeOf(_ request: SentRequest) -> String? {
        guard request.path.hasPrefix("/rest_api/") else { return nil }
        return request.path.split(separator: "/").last.map(String.init)
    }

    /// Mirrors `SimulatedLocalApi.is_sensitive_key`, so the suite can assert the
    /// fixture's predicate rather than re-list its output.
    private static func looksSensitive(_ key: String) -> Bool {
        let lower = key.lowercased()
        let exact = ["m2m.coffeemachinesconfig", "productionwifissid", "cloudbaseurl", "grindersn"]
        if exact.contains(lower) { return true }
        let suffixes = ["password", "passwd", "secret", "token", "logindata", "apikey", "api_key", "credential"]
        return suffixes.contains { lower.hasSuffix($0) }
    }
}
