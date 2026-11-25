import Foundation

// MARK: - Request/response

/// One HTTP request/response pair, with nothing the app does not need.
public struct TransportRequest: Sendable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?

    public init(method: String, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct TransportResponse: Sendable {
    public let status: Int
    public let headers: [String: String]
    /// Every `Set-Cookie` header value, in the order the server sent them.
    public let setCookieHeaders: [String]
    public let body: Data

    public init(status: Int, headers: [String: String], setCookieHeaders: [String], body: Data) {
        self.status = status
        self.headers = headers
        self.setCookieHeaders = setCookieHeaders
        self.body = body
    }

    public var text: String {
        String(data: body, encoding: .utf8) ?? ""
    }
}

/// The narrow transport surface the client needs.  Tests substitute a stub;
/// production uses `URLSession`.
public protocol Transport: Sendable {
    func send(_ request: TransportRequest) async throws -> TransportResponse
}

public enum TransportError: Error, Equatable, Sendable {
    case requestFailed(String)
    case notHTTP
    case redirectRefused(String)
    /// The TLS handshake was refused because the certificate was not the one
    /// the owner opted in for (or normal validation failed).
    case tlsRejected(String)
    /// The target is not on the local network.
    case notLocal(NetworkIsolationError)
    /// The request was addressed to a host other than the configured device.
    case notThisDevice(String)
}

extension TransportError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .requestFailed(let detail):
            return "The request to the grinder failed: \(detail)"
        case .notHTTP:
            return "The grinder returned a non-HTTP response."
        case .redirectRefused(let location):
            return "The grinder answered with a redirect, which this app never follows: \(location)"
        case .tlsRejected(let detail):
            return "TLS trust check failed: \(detail)"
        case .notLocal(let reason):
            return reason.errorDescription
        case .notThisDevice(let url):
            return "Refused a request outside the configured grinder: \(url)"
        }
    }
}

// MARK: - URLSession transport

/// `URLSession` transport, pinned to one endpoint and one trust policy.
///
/// - Local network addresses only, enforced before anything is sent.
/// - No cookie store: the `PHPSESSID` is handled explicitly in the client.
/// - No cache, no credential store.
/// - No redirect following: a 302 is returned to the caller to interpret.
public final class URLSessionTransport: Transport, @unchecked Sendable {
    let endpoint: Endpoint
    let policy: TLSTrustPolicy
    private let timeout: TimeInterval
    private let session: URLSession

    /// Serialises the delegate's shared state with `send`.
    private let stateLock = NSLock()
    private var lastRefusal: TransportError?
    private var capturedCertificate: CertificateInfo?

    /// The leaf certificate seen on the last handshake (setup uses this).
    public var observedCertificate: CertificateInfo? {
        stateLock.lock(); defer { stateLock.unlock() }
        return capturedCertificate
    }

    public init(endpoint: Endpoint, policy: TLSTrustPolicy, timeout: TimeInterval = 20) {
        self.endpoint = endpoint
        self.policy = policy
        self.timeout = timeout

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpAdditionalHeaders = [
            "Accept": "application/json, text/html;q=0.9, */*;q=0.1",
        ]
        // The session keeps a strong reference to its delegate, so a proxy that
        // refers back weakly avoids a retain cycle.
        let proxy = DelegateProxy()
        self.session = URLSession(configuration: configuration, delegate: proxy, delegateQueue: nil)
        proxy.owner = self
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    public func send(_ request: TransportRequest) async throws -> TransportResponse {
        // Bound to the one device: a request for another host, port or scheme is
        // refused before it can leave the app, so this class cannot become a
        // general-purpose client if a future caller builds its own URL.
        guard targetsDevice(request.url) else {
            throw TransportError.notThisDevice(request.url.absoluteString)
        }
        try await NetworkIsolation.requireLocalTarget(endpoint.host)

        var urlRequest = URLRequest(url: request.url, cachePolicy: .reloadIgnoringLocalCacheData)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        urlRequest.timeoutInterval = timeout
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch let error as URLError where error.code == .cancelled {
            if let reason = takeRefusal() { throw reason }
            throw TransportError.requestFailed(error.localizedDescription)
        } catch let error as NetworkIsolationError {
            throw TransportError.notLocal(error)
        } catch {
            throw TransportError.requestFailed(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw TransportError.notHTTP
        }

        var headers: [String: String] = [:]
        for (name, value) in http.allHeaderFields {
            headers[String(describing: name).lowercased()] = String(describing: value)
        }
        let setCookie = http.allHeaderFields
            .filter { String(describing: $0.key).lowercased() == "set-cookie" }
            .map { String(describing: $0.value) }

        return TransportResponse(
            status: http.statusCode,
            headers: headers,
            setCookieHeaders: setCookie,
            body: data
        )
    }

    /// True when `url` addresses exactly the configured device: same scheme,
    /// host and port, and no user info that could disguise another authority.
    public func targetsDevice(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil,
              components.password == nil
        else {
            return false
        }
        let presented = (components.host ?? "").removingPercentEncoding ?? (components.host ?? "")
        let expected = endpoint.host.removingPercentEncoding ?? endpoint.host
        return presented.caseInsensitiveCompare(expected) == .orderedSame
            && (components.port ?? Endpoint.defaultPort) == endpoint.port
    }

    // MARK: - Delegate state

    private func takeRefusal() -> TransportError? {
        stateLock.lock(); defer { stateLock.unlock() }
        defer { lastRefusal = nil }
        return lastRefusal
    }

    func record(refusal: TransportError) {
        stateLock.lock(); defer { stateLock.unlock() }
        lastRefusal = refusal
    }

    func record(certificate: CertificateInfo) {
        stateLock.lock(); defer { stateLock.unlock() }
        if capturedCertificate == nil { capturedCertificate = certificate }
    }

    /// Answers `URLSession`'s delegate callbacks on behalf of the transport,
    /// which cannot be its own delegate before `init` returns.
    private final class DelegateProxy: NSObject, URLSessionDataDelegate, @unchecked Sendable {
        weak var owner: URLSessionTransport?

        /// Refuse every redirect: following one would mean contacting another host.
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest
        ) async -> URLRequest? {
            owner?.record(refusal: .redirectRefused(
                request.url?.absoluteString ?? response.url?.absoluteString ?? "unknown"
            ))
            return nil
        }

        /// Capture the leaf certificate during setup, and enforce the pin for a
        /// device the owner has opted in for.  With no policy the system decides.
        func urlSession(
            _ session: URLSession,
            didReceive challenge: URLAuthenticationChallenge
        ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust,
                  let leaf = CertificateInspection.leafCertificate(trust: trust),
                  let owner
            else {
                return (.performDefaultHandling, nil)
            }

            let info = CertificateInspection.info(certificate: leaf)
            if let info { owner.record(certificate: info) }

            switch decideTrust(presented: info?.sha256, policy: owner.policy) {
            case .acceptPinned:
                return (.useCredential, URLCredential(trust: trust))
            case .useDefault:
                return (.performDefaultHandling, nil)
            case .reject:
                owner.record(refusal: .tlsRejected(
                    "the certificate presented is not the one accepted for this grinder"
                ))
                return (.cancelAuthenticationChallenge, nil)
            }
        }
    }
}
