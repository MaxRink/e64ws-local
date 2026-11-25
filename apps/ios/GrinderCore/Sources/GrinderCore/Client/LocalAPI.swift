import Foundation

/// The read-only Local Owner API client.
///
/// Every route needs both credentials: the vendor `PHPSESSID` cookie and the
/// owner token from `/db/e64local/token`, sent as `X-E64-Local-Token`.
///
/// This client deliberately exposes **read-only data routes only**.  The
/// `ws_token` route mints a WSS credential that authorises commands, so it is
/// absent from the API: the app never mints a control credential.
public actor LocalAPI {
    public static let apiVersion = "1"
    public static let schema = "e64local-api-v1"
    public static let tokenHeader = "X-E64-Local-Token"

    /// Routes this client will call.  `ws_token` is intentionally absent.
    public static let dataRoutes: Set<String> = [
        "capabilities", "machine", "grind_log", "service_log", "alert_log",
        "portafilters", "recipes", "settings", "config", "file",
    ]

    private let endpoint: Endpoint
    private let transport: Transport
    private let ownerToken: OwnerToken?
    private let session: VendorSession?

    public init(
        endpoint: Endpoint,
        transport: Transport,
        ownerToken: OwnerToken? = nil,
        session: VendorSession? = nil
    ) {
        self.endpoint = endpoint
        self.transport = transport
        self.ownerToken = ownerToken
        self.session = session
    }

    // MARK: - Handshake and identity

    public func capabilities() async throws -> Capabilities {
        try unwrap(try await post("capabilities", body: [:]))
    }

    public func machine() async throws -> Machine {
        try unwrap(try await post("machine", body: [:]))
    }

    /// The handshake setup verifies with: success only on a valid
    /// `capabilities` document (docs/openapi/local-api.yaml).
    public func verifyHandshake() async throws -> Capabilities {
        // Verification is the setup success gate, and the device only answers it
        // with both factors.  Refuse to attempt it with one, so a caller cannot
        // mistake the dispatcher's refusal for a verified install.
        guard ownerToken != nil else {
            throw APIError.unexpectedResponse("verification needs the owner token")
        }
        guard session != nil else {
            throw APIError.unexpectedResponse("verification needs the vendor session")
        }
        let capabilities = try await capabilities()
        guard capabilities.apiVersion == Self.apiVersion else {
            throw APIError.unexpectedResponse(
                "the grinder reports API version \(capabilities.apiVersion), this app speaks \(Self.apiVersion)"
            )
        }
        let missing = Self.dataRoutes.subtracting(capabilities.routes)
        guard missing.isEmpty else {
            throw APIError.unexpectedResponse(
                "the grinder does not expose: \(missing.sorted().joined(separator: ", "))"
            )
        }
        return capabilities
    }

    // MARK: - Logs

    public func log(_ kind: LogKind, query: LogQuery? = nil) async throws -> LogPage {
        // The per-route default limit (20 for grinds, 500 for the other logs) is
        // applied here rather than in a `try!` default argument.
        let query = try query ?? LogQuery(limit: kind.defaultLimit)
        var body: [String: AnyEncodable] = [
            "limit": .int(query.limit),
            "offset": .int(query.offset),
        ]
        if let since = query.since { body["since"] = .string(since) }
        if let until = query.until { body["until"] = .string(until) }
        return try unwrap(try await post(kind.rawValue, body: body))
    }

    // MARK: - Data

    public func portafilters() async throws -> RowTable {
        try unwrap(try await post("portafilters", body: [:]))
    }

    public func recipes() async throws -> RowTable {
        try unwrap(try await post("recipes", body: [:]))
    }

    public func settings() async throws -> SettingsExport {
        try unwrap(try await post("settings", body: [:]))
    }

    public func config() async throws -> ConfigExport {
        try unwrap(try await post("config", body: [:]))
    }

    /// One allowlisted file.  The path is checked client-side first; the device
    /// enforces the same allowlist again with `realpath`.
    public func file(path: String) async throws -> FileContent {
        guard FileAllowlist.isAllowed(path) else {
            throw LocalAPIError(code: 400, message: "“\(path)” is not a file this app may read")
        }
        return try unwrap(try await post("file", body: ["path": .string(path)]))
    }

    // MARK: - Requests

    private func post<T: Decodable>(
        _ route: String,
        body: [String: AnyEncodable]
    ) async throws -> Envelope<T> {
        guard Self.dataRoutes.contains(route) else {
            throw LocalAPIError(code: 400, message: "“\(route)” is not a route this app calls")
        }

        var headers: [String: String] = [
            "Content-Type": "application/json",
            "Accept": "application/json",
        ]
        // The header is preferred over the JSON `token` fallback, so the secret
        // is not duplicated in the body.
        if let token = ownerToken {
            headers[Self.tokenHeader] = token.value
        }
        if let session {
            headers["Cookie"] = session.cookieHeader
        }

        let url = endpoint.url(path: "/rest_api/\(route)")
        let response = try await transport.send(
            TransportRequest(
                method: "POST",
                url: url,
                headers: headers,
                body: try body.encoded()
            )
        )
        return try Self.decode(response)
    }

    /// Decode the vendor envelope.  HTTP 200 is success and HTTP 400 is every
    /// handled failure, so the body's `errorCode` is authoritative.
    static func decode<T: Decodable>(_ response: TransportResponse) throws -> Envelope<T> {
        guard !response.body.isEmpty else {
            throw APIError.unexpectedResponse("the grinder returned an empty body")
        }
        do {
            return try JSONDecoder().decode(Envelope<T>.self, from: response.body)
        } catch {
            throw APIError.decodingFailed(error.localizedDescription)
        }
    }

    private func unwrap<T: Decodable>(_ envelope: Envelope<T>) throws -> T {
        if envelope.success, let data = envelope.data {
            return data
        }
        if envelope.errorCode == 0 {
            throw APIError.unexpectedResponse("the grinder reported success without data")
        }
        // errorCode 401 is the owner token: a session problem is not the same
        // thing, and the app never asks the owner to re-enter a token it has.
        throw LocalAPIError(
            code: envelope.errorCode,
            message: envelope.error ?? "request failed",
            console: envelope.console
        )
    }
}

/// Failures that are not the module's `errorCode`.
public enum APIError: Error, Equatable {
    case unexpectedResponse(String)
    case decodingFailed(String)
}

extension APIError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unexpectedResponse(let detail):
            return "The grinder returned an unexpected response: \(detail)"
        case .decodingFailed(let detail):
            return "The grinder's reply could not be read: \(detail)"
        }
    }
}
