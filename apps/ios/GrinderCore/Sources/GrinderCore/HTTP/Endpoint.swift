import Foundation

/// The single device the app talks to.
///
/// Parsing mirrors `tools/e64root/target.py::parse_endpoint`: a hostname or IP,
/// an optional port, and bracketed IPv6 literals.  A URL or a path is rejected
/// so a paste of `https://…/rest_api` cannot silently become the base URL.
public struct Endpoint: Hashable, Sendable, CustomStringConvertible {
    public static let defaultPort = 443

    public let host: String
    public let port: Int

    /// Restricted to hostname/IP characters plus `:` and `%` (IPv6 scope ids).
    private static let allowedHostCharacters = CharacterSet(
        charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-%"
    )

    public init(host: String, port: Int = Endpoint.defaultPort) throws {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw EndpointError.emptyHost }
        if trimmed.contains("://") { throw EndpointError.looksLikeURL }
        if trimmed.contains("/") { throw EndpointError.looksLikePath }
        guard trimmed.unicodeScalars.allSatisfy(Self.allowedHostCharacters.contains),
              !trimmed.contains("..")
        else {
            throw EndpointError.invalidHostCharacters
        }
        guard (1...65535).contains(port) else {
            throw EndpointError.portOutOfRange(port)
        }
        self.host = trimmed
        self.port = port
    }

    /// Parse `host`, `host:port` or `[v6]:port`.
    public init(hostAndPort value: String, defaultPort: Int = Endpoint.defaultPort) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw EndpointError.emptyHost }
        if trimmed.contains("://") { throw EndpointError.looksLikeURL }
        if trimmed.contains("/") { throw EndpointError.looksLikePath }

        if trimmed.hasPrefix("[") {
            guard let closing = trimmed.firstIndex(of: "]") else {
                throw EndpointError.unterminatedIPv6
            }
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<closing])
            let tail = String(trimmed[trimmed.index(after: closing)...])
            if tail.isEmpty {
                try self.init(host: host, port: defaultPort)
            } else if tail.hasPrefix(":") {
                try self.init(host: host, port: Self.parsePort(String(tail.dropFirst())))
            } else {
                throw EndpointError.invalidHostCharacters
            }
            return
        }

        let colons = trimmed.filter { $0 == ":" }.count
        if colons == 1, let separator = trimmed.lastIndex(of: ":") {
            let host = String(trimmed[..<separator])
            let portText = String(trimmed[trimmed.index(after: separator)...])
            try self.init(host: host, port: Self.parsePort(portText))
        } else {
            // No port, or a bare IPv6 literal (which needs brackets to take a port).
            try self.init(host: trimmed, port: defaultPort)
        }
    }

    private static func parsePort(_ text: String) throws -> Int {
        guard !text.isEmpty, text.allSatisfy({ $0.isASCII && $0.isNumber }),
              let port = Int(text)
        else {
            throw EndpointError.invalidPort(text)
        }
        return port
    }

    /// `host` or `[host]:port`, for the `Host:` header and logs.
    public var authority: String {
        let shown = host.contains(":") ? "[\(host)]" : host
        return port == Self.defaultPort ? shown : "\(shown):\(port)"
    }

    /// The single base URL the client will ever contact.
    ///
    /// The default port is omitted, because `URLSession` refuses to set a
    /// `Host` header carrying an explicit `:443` (HTTP 400 from URLSession
    /// itself) — the same reason `curl` omits it.
    public var baseURL: URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        if port != Self.defaultPort {
            components.port = port
        }
        // URLComponents.host rejects some inputs it considers invalid; the
        // fallback keeps the URL well-formed for the URLSession layer, which
        // validates again before connecting.
        if components.url == nil {
            let encoded = host.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? host
            components.percentEncodedHost = encoded
        }
        return components.url ?? URL(string: "https://127.0.0.1")!
    }

    public func url(path: String) -> URL {
        let base = baseURL
        let trimmedPath = path.hasPrefix("/") ? path : "/" + path
        return URL(string: trimmedPath, relativeTo: base)?.absoluteURL ?? base
    }

    public var description: String { authority }
}

public enum EndpointError: Error, Equatable, LocalizedError {
    case emptyHost
    case looksLikeURL
    case looksLikePath
    case invalidHostCharacters
    case invalidPort(String)
    case portOutOfRange(Int)
    case unterminatedIPv6

    public var errorDescription: String? {
        switch self {
        case .emptyHost: return "Enter the grinder's IP address or host name."
        case .looksLikeURL: return "Enter only the host, not a URL (no https://)."
        case .looksLikePath: return "Enter only the host, without a path."
        case .invalidHostCharacters: return "The host contains characters that are not allowed."
        case .invalidPort(let text): return "“\(text)” is not a valid port."
        case .portOutOfRange(let port): return "Port \(port) is outside 1–65535."
        case .unterminatedIPv6: return "Bracket the IPv6 address, for example [fe80::1]:443."
        }
    }
}
