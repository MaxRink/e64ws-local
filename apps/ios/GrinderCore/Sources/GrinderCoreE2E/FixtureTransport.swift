import Foundation
import GrinderCore

/// One request the harness actually put on the wire, as it was sent: after the
/// fixture credential was attached and before any response was read.
struct SentRequest: Sendable {
    let method: String
    let url: URL
    let headers: [String: String]
    let body: Data

    var path: String { url.path }
    var bodyText: String { String(data: body, encoding: .utf8) ?? "" }

    /// A header value, matched case-insensitively the way HTTP does.
    func header(_ name: String) -> String? {
        if let direct = headers[name] { return direct }
        let lower = name.lowercased()
        return headers.first { $0.key.lowercased() == lower }?.value
    }
}

/// The live transport: `URLSession` bound to the harness base URL.
///
/// `GrinderCore` already ships `URLSessionTransport`, and this target does not
/// use it on purpose: `targetsDevice` requires `https` and pins the certificate
/// the owner opted in for, while the fixture runs on plain `http://127.0.0.1`.
/// Teaching the production transport a plain-HTTP mode would trade a TLS
/// property for a test, so the harness carries its own transport instead and
/// leaves the shipped one untouched.
///
/// What this transport keeps from the shipped one:
///
///  * **One authority.**  A request for another host or port is refused before
///    it can leave the process, so the suite cannot reach anything but the URL
///    the harness handed it.
///  * **No ambient credentials.**  No cookie store, no cache, no credential
///    store: the session cookie is passed explicitly, as the clients do.
///  * **No redirects.**  A 3xx is returned to the caller, never followed, so a
///    redirect cannot become a second, unchecked host.
///
/// It adds nothing to the credential: the fixture is started with a 64-hex
/// owner token, `OwnerToken` holds exactly that value, and the header the client
/// writes is the header that goes on the wire.  Every request is recorded, so
/// the suite can prove what was sent.
final class FixtureTransport: Transport, @unchecked Sendable {
    let baseURL: URL
    let token: String
    private let timeout: TimeInterval
    private let session: URLSession
    private let redirects = RedirectBlocker()

    private let stateLock = NSLock()
    private var recorded: [SentRequest] = []

    init(baseURL: URL, token: String, timeout: TimeInterval = 20) {
        self.baseURL = baseURL
        self.token = token
        self.timeout = timeout

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        self.session = URLSession(
            configuration: configuration,
            delegate: redirects,
            delegateQueue: nil
        )
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    /// Every request this transport has sent, in order.
    func sentRequests() -> [SentRequest] {
        stateLock.lock()
        defer { stateLock.unlock() }
        return recorded
    }

    func send(_ request: TransportRequest) async throws -> TransportResponse {
        guard let target = pinnedURL(for: request.url) else {
            throw TransportError.notThisDevice(request.url.absoluteString)
        }

        var headers = request.headers

        var urlRequest = URLRequest(url: target, cachePolicy: .reloadIgnoringLocalCacheData)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        urlRequest.timeoutInterval = timeout
        for (name, value) in headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }

        // Recorded before the await, so "nothing was sent" is provable even when
        // the peer refuses or the connection drops.
        record(SentRequest(
            method: request.method,
            url: target,
            headers: headers,
            body: request.body ?? Data()
        ))

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch {
            throw TransportError.requestFailed(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw TransportError.notHTTP
        }

        var responseHeaders: [String: String] = [:]
        for (name, value) in http.allHeaderFields {
            responseHeaders[String(describing: name).lowercased()] = String(describing: value)
        }
        var setCookie = http.allHeaderFields
            .filter { String(describing: $0.key).lowercased() == "set-cookie" }
            .map { String(describing: $0.value) }
        if setCookie.isEmpty, let combined = http.value(forHTTPHeaderField: "Set-Cookie") {
            setCookie = [combined]
        }

        return TransportResponse(
            status: http.statusCode,
            headers: responseHeaders,
            setCookieHeaders: setCookie,
            body: data
        )
    }

    /// The request URL, re-rooted on the harness base URL.
    ///
    /// `GrinderCore` builds every URL as `https://<host>:<port>/<path>` because a
    /// device is HTTPS; the harness re-points that at the scheme and origin it
    /// was given, and refuses anything addressed elsewhere.
    private func pinnedURL(for url: URL) -> URL? {
        guard let host = url.host, let baseHost = baseURL.host,
              host.caseInsensitiveCompare(baseHost) == .orderedSame
        else { return nil }
        let requestPort = url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)
        guard requestPort == port else { return nil }
        guard let path = url.path.isEmpty ? nil : url.path else { return nil }

        var components = URLComponents()
        components.scheme = baseURL.scheme
        components.host = baseHost
        if let basePort = baseURL.port { components.port = basePort }
        components.percentEncodedPath = path
        if let query = url.query { components.percentEncodedQuery = query }
        return components.url
    }

    private var port: Int {
        baseURL.port ?? (baseURL.scheme?.lowercased() == "https" ? 443 : 80)
    }

    private func record(_ request: SentRequest) {
        stateLock.lock()
        recorded.append(request)
        stateLock.unlock()
    }
}

/// Refuse every redirect, so a 3xx can never turn into a request to a host the
/// harness did not choose.
private final class RedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}

/// A reply read as plain JSON, for the fixture routes that no shipped client
/// models (the vendor session handshake and the raw action probes).
struct FixtureReply: Sendable {
    let status: Int
    let headers: [String: String]
    let setCookie: [String]
    let body: Data

    var text: String { String(data: body, encoding: .utf8) ?? "" }

    var object: [String: Any] {
        (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
    }

    func string(_ key: String) -> String? { object[key] as? String }

    func int(_ key: String) -> Int? { (object[key] as? NSNumber)?.intValue }

    func bool(_ key: String) -> Bool? { (object[key] as? NSNumber)?.boolValue }

    func header(_ name: String) -> String? {
        let lower = name.lowercased()
        return headers.first { $0.key.lowercased() == lower }?.value
    }
}

extension FixtureTransport {
    /// A JSON `POST` to the fixture, with the two factors attached the way the
    /// clients attach them: token in the header, session in the cookie.
    func post(
        _ path: String,
        json: [String: Any],
        authorized: Bool = true,
        cookie: String? = nil
    ) async throws -> FixtureReply {
        var headers: [String: String] = ["Content-Type": "application/json"]
        if authorized { headers[LocalAPI.tokenHeader] = token }
        if let cookie { headers["Cookie"] = cookie }
        let body = try JSONSerialization.data(withJSONObject: json)
        return reply(try await send(TransportRequest(
            method: "POST",
            url: pathURL(path),
            headers: headers,
            body: body
        )))
    }

    func get(
        _ path: String,
        authorized: Bool = true,
        cookie: String? = nil
    ) async throws -> FixtureReply {
        var headers: [String: String] = [:]
        if authorized { headers[LocalAPI.tokenHeader] = token }
        if let cookie { headers["Cookie"] = cookie }
        return reply(try await send(TransportRequest(
            method: "GET",
            url: pathURL(path),
            headers: headers
        )))
    }

    /// Path on the harness authority, in the shape the clients build (the
    /// transport re-roots the scheme).
    private func pathURL(_ path: String) -> URL {
        let trimmed = path.hasPrefix("/") ? path : "/" + path
        return URL(string: trimmed, relativeTo: baseURL)?.absoluteURL ?? baseURL
    }

    private func reply(_ response: TransportResponse) -> FixtureReply {
        FixtureReply(
            status: response.status,
            headers: response.headers,
            setCookie: response.setCookieHeaders,
            body: response.body
        )
    }
}
