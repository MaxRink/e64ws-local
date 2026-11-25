import Foundation

extension Transport {
    /// Send a request to a path on `endpoint`.
    public func send(
        endpoint: Endpoint,
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: Data? = nil
    ) async throws -> TransportResponse {
        try await send(
            TransportRequest(
                method: method,
                url: endpoint.url(path: path),
                headers: headers,
                body: body
            )
        )
    }

    /// A `POST` of `body` as JSON to one of the local API routes.
    public func postJSON<T: Encodable>(
        endpoint: Endpoint,
        route: String,
        body: T,
        token: OwnerToken?,
        session: VendorSession?
    ) async throws -> TransportResponse {
        var headers: [String: String] = [
            "Content-Type": "application/json",
            "Accept": "application/json",
        ]
        // The header is preferred over the JSON `token` fallback, so the secret
        // is not duplicated in the body.
        if let token {
            headers[LocalAPI.tokenHeader] = token.value
        }
        if let session {
            headers["Cookie"] = session.cookieHeader
        }
        return try await send(
            endpoint: endpoint,
            method: "POST",
            path: "/rest_api/\(route)",
            headers: headers,
            body: try JSONEncoder().encode(body)
        )
    }
}

/// Redaction, so a token or a session id can never reach a log.
///
/// The app never logs request bodies or headers.  If anything ever needs to be
/// printed for diagnosis it goes through this first: secret-shaped values are
/// replaced and nothing recognisable is retained.
public enum LogRedaction {
    /// The same shapes the module's text redactor removes (docs/LOCAL_API.md §9).
    private static let patterns: [String] = [
        "(?i)(password|passwd|pwd|psk|pass|secret|token|bearer|session|ssid)\\s*[:=]\\s*\"?[^\\s\"'&]+",
        "(?i)\\bSN[\\s:#=_-]*[A-Za-z0-9-]{4,}",
        "(?i)\\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\\b",
        "\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b",
    ]

    /// Replace anything secret-shaped in `text`.
    public static func redact(_ text: String) -> String {
        var output = text
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern) else {
                // A broken pattern must never leak the original text.
                return "<redacted>"
            }
            output = regex.stringByReplacingMatches(
                in: output,
                range: NSRange(output.startIndex..., in: output),
                withTemplate: "<redacted>"
            )
        }
        return output
    }

    /// True when `text` looks like it contains a secret the app holds.
    public static func looksSecret(_ text: String) -> Bool {
        redact(text) != text
    }
}
