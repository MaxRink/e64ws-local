import Foundation

/// Obtains and keeps the vendor PHP session for the one device.
///
/// `POST /login.php` with `login=1`, `userRole=Owner` and the Owner password is
/// the documented login (docs/LOCAL_API.md §2.3).  A fresh `GET /login.php`
/// first makes sure the response carries the `PHPSESSID` cookie even on a unit
/// where the page auto-logs in an Owner with no password (SEC-32), which is
/// visible in the fingerprint as a `302` to `index.php`.
public actor SessionAuthenticator {
    private let transport: Transport
    private let endpoint: Endpoint

    public init(transport: Transport, endpoint: Endpoint) {
        self.transport = transport
        self.endpoint = endpoint
    }

    public func signIn(password: String) async throws -> LoginOutcome {
        // A fresh page load establishes the cookie jar's session.
        let page = try? await transport.send(
            TransportRequest(
                method: "GET",
                url: endpoint.url(path: "/login.php"),
                headers: ["Accept": "text/html, */*;q=0.1"]
            )
        )
        let existing = page.flatMap {
            CookieHeader.sessionCookie(from: $0.setCookieHeaders).flatMap(VendorSession.init)
        }

        var headers: [String: String] = [
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html, application/json;q=0.9, */*;q=0.1",
        ]
        if let existing { headers["Cookie"] = existing.cookieHeader }

        let response = try await transport.send(
            TransportRequest(
                method: "POST",
                url: endpoint.url(path: "/login.php"),
                headers: headers,
                body: VendorLogin.body(password: password)
            )
        )

        let session = CookieHeader.sessionCookie(from: response.setCookieHeaders)
            .flatMap(VendorSession.init) ?? existing
        let redirectedToIndex = (300...399).contains(response.status)
            && (response.headers["location"] ?? "").lowercased().contains("index.php")
        let sawBearer = response.headers["authorization"]?.hasPrefix("Bearer") ?? false

        guard let session else {
            throw AuthError.noSession
        }

        // The vendor's documented success signal is the redirect to index.php;
        // a re-rendered login form means the password was rejected.
        let renderedLoginForm = response.status == 200
            && VendorLogin.isSessionValid(response.text) == false
            && response.text.contains("name=\"password\"")
        if renderedLoginForm && !redirectedToIndex {
            throw AuthError.wrongPassword
        }

        return LoginOutcome(
            sessionEstablished: redirectedToIndex || response.status == 200,
            session: session,
            sawAuthorizationHeader: sawBearer
        )
    }

    /// `check_session` returns `session_valid` / `session_invalid` for a live
    /// check without the owner token.
    public func isSessionValid(_ session: VendorSession) async throws -> Bool {
        let response = try await transport.send(
            TransportRequest(
                method: "POST",
                url: endpoint.url(path: "/rest_api/check_session"),
                headers: [
                    "Cookie": session.cookieHeader,
                    "Content-Type": "application/json",
                ],
                body: Data("{}".utf8)
            )
        )
        return VendorLogin.isSessionValid(response.text)
    }
}
