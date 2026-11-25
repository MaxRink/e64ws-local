import Foundation
import GrinderCore

// MARK: - Local API client

/// A stub transport that records requests and replays canned responses.
actor StubTransport: Transport {
    private var responses: [String: TransportResponse]
    private(set) var requests: [TransportRequest] = []
    private var failure: TransportError?

    init(responses: [String: TransportResponse] = [:], failure: TransportError? = nil) {
        self.responses = responses
        self.failure = failure
    }

    func send(_ request: TransportRequest) async throws -> TransportResponse {
        requests.append(request)
        if let failure { throw failure }
        let route = request.url.path.split(separator: "/").last.map(String.init) ?? ""
        if let response = responses[route] { return response }
        return TransportResponse(
            status: 400,
            headers: [:],
            setCookieHeaders: [],
            body: Data(#"{"success":false,"errorCode":401,"error":"owner token required"}"#.utf8)
        )
    }

    func requestPaths() -> [String] { requests.map(\.url.path) }
}

func jsonResponse(_ json: String, status: Int = 200, setCookie: [String] = []) -> TransportResponse {
    TransportResponse(status: status, headers: [:], setCookieHeaders: setCookie, body: Data(json.utf8))
}

let capabilitiesJSON = """
{
  "data": {
    "schema": "e64local-api-v1",
    "route": "capabilities",
    "apiVersion": "1",
    "routes": ["alert_log","capabilities","config","file","grind_log","machine","portafilters","recipes","service_log","settings","ws_token"],
    "features": {"pagination": true, "timeFilters": true, "logRowTypes": "strings", "recipeExport": "json",
                 "csvExport": false, "singleRecipe": false, "machineIdentity": "serial-sha256",
                 "wssToken": true, "actions": false},
    "limits": {"maxRows": 5000, "defaultRows": {"alert_log": 500, "grind_log": 20, "service_log": 500},
               "maxOffset": 1000000, "maxFileBytes": 1048576, "maxRequestBytes": 16384},
    "serverTime": 1767225600,
    "devMode": true
  },
  "success": true,
  "errorCode": 0
}
"""

let machineJSON = """
{
  "data": {
    "schema": "e64local-api-v1", "route": "machine", "variant": "Hsg", "model": "E64 WS",
    "grinderType": 5, "grinderTypeName": "E64 WS", "grinderSubType": 0,
    "firmware": "development image, VERSION: HEM-HSG.140-git-g273ab65 (built at <redacted>)",
    "devMode": true, "serialPresent": true,
    "serialSha256": "\(String(repeating: "a1", count: 32))",
    "serialNote": "the raw serial number is never returned by this API"
  },
  "success": true, "errorCode": 0
}
"""

let grindLogJSON = """
{
  "data": {
    "schema": "e64local-api-v1", "route": "grind_log",
    "rows": [
      {"grind_id": "123", "grind_uuid": "00000000-0000-4000-8000-000000000001",
       "grind_date_time": "2026-01-01 12:00:00", "recipe_index": "1", "grind_ddd": "500",
       "grind_duration": "25000", "grind_weight": "18000", "grind_successfull": "1",
       "grind_debug_data": "<redacted>", "recipe_mode": "GbW", "recipe_amount": "18000"}
    ],
    "count": 1, "limit": 20, "offset": 0, "since": null, "until": null, "hasMore": false
  },
  "success": true, "errorCode": 0
}
"""

func apiChecks() -> [CheckCase] {
    let endpoint = try! Endpoint(host: "192.168.1.100")
    let token = OwnerToken.generate()
    let session = VendorSession(sessionID: "sess123")

    return [
        CheckCase("api: capabilities decodes the documented document") {
            let stub = StubTransport(responses: ["capabilities": jsonResponse(capabilitiesJSON)])
            let api = LocalAPI(endpoint: endpoint, transport: stub)
            let capabilities = try await api.capabilities()
            try checkEqual(capabilities.apiVersion, "1")
            try checkEqual(capabilities.features.actions, false, "actions must be false")
            try checkEqual(capabilities.limits.maxRows, 5000)
            try checkEqual(capabilities.limits.defaultRows["grind_log"], 20)
        },
        CheckCase("api: the handshake rejects a device missing a data route") {
            let reduced = capabilitiesJSON.replacingOccurrences(of: "\"recipes\",", with: "")
            let stub = StubTransport(responses: ["capabilities": jsonResponse(reduced)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token, session: session)
            var threw = false
            do { _ = try await api.verifyHandshake() } catch { threw = true }
            try check(threw, "a missing route must fail the handshake")
        },
        CheckCase("api: the handshake accepts the full document") {
            let stub = StubTransport(responses: ["capabilities": jsonResponse(capabilitiesJSON)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token, session: session)
            _ = try await api.verifyHandshake()
        },
        CheckCase("api: verification refuses to run without both factors") {
            let stub = StubTransport(responses: ["capabilities": jsonResponse(capabilitiesJSON)])
            var threw = false
            do {
                _ = try await LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
                    .verifyHandshake()
            } catch { threw = true }
            try check(threw, "the owner token alone must not verify an install")
            threw = false
            do {
                _ = try await LocalAPI(endpoint: endpoint, transport: stub, session: session)
                    .verifyHandshake()
            } catch { threw = true }
            try check(threw, "the vendor session alone must not verify an install")
            _ = try await LocalAPI(
                endpoint: endpoint,
                transport: stub,
                ownerToken: token,
                session: session
            ).verifyHandshake()
        },
        CheckCase("api: every request carries the owner token header and the session cookie") {
            let stub = StubTransport(responses: [
                "capabilities": jsonResponse(capabilitiesJSON),
                "machine": jsonResponse(machineJSON),
            ])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token, session: session)
            _ = try await api.machine()
            let request = try checkNotNil(await stub.requests.first, "request")
            try checkEqual(request.method, "POST")
            try checkEqual(request.url.absoluteString, "https://192.168.1.100/rest_api/machine")
            try checkEqual(request.headers["X-E64-Local-Token"], token.value)
            try checkEqual(request.headers["Cookie"], "PHPSESSID=sess123")
            try checkEqual(request.headers["Content-Type"], "application/json")
            try checkEqual(String(data: request.body ?? Data(), encoding: .utf8), "{}")
        },
        CheckCase("api: the machine document decodes the hashed serial") {
            let stub = StubTransport(responses: ["machine": jsonResponse(machineJSON)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            let machine = try await api.machine()
            try checkEqual(machine.model, "E64 WS")
            try checkEqual(machine.serialSha256?.count, 64)
            try checkEqual(machine.devMode, true)
            try check(machine.serialNote.contains("never returned"), "serial note")
        },
        CheckCase("api: a 400 with errorCode 401 surfaces as the owner-token error, not a session error") {
            let stub = StubTransport()
            let api = LocalAPI(endpoint: endpoint, transport: stub)
            var caught: Error?
            do { _ = try await api.capabilities() } catch { caught = error }
            let error = try checkNotNil(caught as? LocalAPIError, "LocalAPIError")
            try checkEqual(error.code, 401)
            try check(error.userMessage.contains("owner token"), "message should mention the owner token")
        },
        CheckCase("api: HTTP 403 dev-gate is reported as a dev-mode problem") {
            let stub = StubTransport(responses: [
                "capabilities": jsonResponse(#"{"error":"dev mode required","success":false,"errorCode":403}"#, status: 403),
            ])
            let api = LocalAPI(endpoint: endpoint, transport: stub)
            var caught: Error?
            do { _ = try await api.capabilities() } catch { caught = error }
            let error = try checkNotNil(caught as? LocalAPIError, "LocalAPIError")
            try check(error.userMessage.contains("development image"), "message should mention the development image")
        },
        CheckCase("api: the route table is exactly the documented read-only set") {
            let documented: Set<String> = [
                "alert_log", "capabilities", "config", "file", "grind_log",
                "machine", "portafilters", "recipes", "service_log", "settings",
            ]
            try checkEqual(LocalAPI.dataRoutes, documented, "routes")
            try check(!LocalAPI.dataRoutes.contains("ws_token"), "ws_token must never be a route")
            var threw = false
            do {
                _ = try await LocalAPI(endpoint: endpoint, transport: StubTransport(), ownerToken: token)
                    .file(path: "/db/e64local/token")
            } catch { threw = true }
            try check(threw, "the token file is not a readable path")
        },
        CheckCase("api: grind_log rows decode as strings without losing the page metadata") {
            let stub = StubTransport(responses: ["grind_log": jsonResponse(grindLogJSON)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            let page = try await api.log(.grind, query: try LogQuery(limit: 20))
            try checkEqual(page.route, "grind_log")
            try checkEqual(page.rows.count, 1)
            try checkEqual(page.rows[0]["grind_weight"], "18000")
            try checkEqual(page.hasMore, false)
            try checkEqual(page.nextOffset, 1)
        },
        CheckCase("api: the log query body carries limit, offset and filters") {
            let stub = StubTransport(responses: ["service_log": jsonResponse(grindLogJSON)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            _ = try? await api.log(.service, query: try LogQuery(limit: 100, offset: 200, since: "2026-01-01", until: "2026-01-31"))
            let request = try checkNotNil(await stub.requests.first, "request")
            let body = try JSONDecoder().decode([String: DecodableValue].self, from: request.body ?? Data())
            try checkEqual(body["limit"]?.intValue, 100)
            try checkEqual(body["offset"]?.intValue, 200)
            try checkEqual(body["since"]?.stringValue, "2026-01-01")
            try checkEqual(body["until"]?.stringValue, "2026-01-31")
        },
        CheckCase("api: the per-route default limit is applied") {
            let stub = StubTransport(responses: ["service_log": jsonResponse(grindLogJSON)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            _ = try? await api.log(.service)
            let request = try checkNotNil(await stub.requests.first, "request")
            let body = try JSONDecoder().decode([String: DecodableValue].self, from: request.body ?? Data())
            try checkEqual(body["limit"]?.intValue, 500, "service_log default")
            try checkEqual(body["offset"]?.intValue, 0)
        },
        CheckCase("api: an alert_log page with a note decodes") {
            let json = """
            {"data": {"schema":"e64local-api-v1","route":"alert_log","rows":[],"count":0,"limit":500,
              "offset":0,"since":null,"until":null,"hasMore":false,
              "note":"alert_log table not present on this firmware"},"success":true,"errorCode":0}
            """
            let stub = StubTransport(responses: ["alert_log": jsonResponse(json)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            let page = try await api.log(.alert, query: try LogQuery(limit: 500))
            try checkEqual(page.note, "alert_log table not present on this firmware")
            try checkEqual(page.rows.count, 0)
        },
        CheckCase("api: settings keep values as strings and list redacted keys") {
            let json = """
            {"data": {"schema":"e64local-api-v1","route":"settings",
              "settings": {"Cloud.ConnectionEnabled":"true","Grinding.OvershootWeight":"536960"},
              "redacted": ["Role.Owner.LoginData","Wifi.StaPassword"], "count": 2},
             "success": true, "errorCode": 0}
            """
            let stub = StubTransport(responses: ["settings": jsonResponse(json)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            let export = try await api.settings()
            try checkEqual(export.settings["Cloud.ConnectionEnabled"], "true")
            try checkEqual(export.redacted.count, 2)
        },
        CheckCase("api: config keeps JSON types and renders them") {
            let json = """
            {"data": {"schema":"e64local-api-v1","route":"config",
              "config": {"targetWeightGr": 18.0, "grindTimeSec": 30.5, "grinderSn": "<redacted>",
                         "nested": {"password": "<redacted>", "keep": "ok"}},
              "redacted": ["grinderSn","nested.password"]}, "success": true, "errorCode": 0}
            """
            let stub = StubTransport(responses: ["config": jsonResponse(json)])
            let api = LocalAPI(endpoint: endpoint, transport: stub, ownerToken: token)
            let export = try await api.config()
            try checkEqual(export.config["targetWeightGr"], .number(18))
            try checkEqual(export.config["grinderSn"], .string("<redacted>"))
            try checkEqual(export.config["nested"]?.displayText, "keep: ok, password: <redacted>")
        },
        CheckCase("api: an empty body is an unexpected response, not a crash") {
            let stub = StubTransport(responses: [
                "capabilities": TransportResponse(status: 200, headers: [:], setCookieHeaders: [], body: Data()),
            ])
            let api = LocalAPI(endpoint: endpoint, transport: stub)
            var threw = false
            do { _ = try await api.capabilities() } catch { threw = true }
            try check(threw, "an empty body must throw")
        },
    ]
}

/// Decode an arbitrary JSON scalar in a test body.
enum DecodableValue: Decodable {
    case int(Int)
    case string(String)
    case other

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else {
            self = .other
        }
    }

    var intValue: Int? { if case .int(let value) = self { return value }; return nil }
    var stringValue: String? { if case .string(let value) = self { return value }; return nil }
}
