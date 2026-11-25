import Foundation
import GrinderCore

/// Reachability and containment, before anything else runs.
///
/// The contract says "no network beyond 127.0.0.1".  This suite enforces that
/// with the shipped classifier rather than by trusting its own configuration: a
/// base URL that resolves anywhere else is a failure, not a warning.
enum PreflightSuite {
    static func run(_ h: Harness) async throws {
        try h.checks.expect(
            NetworkIsolation.isNumericAddress(h.config.host),
            "preflight: the harness target is a numeric address (\(h.config.host))"
        )
        try h.checks.expect(
            NetworkIsolation.isPrivateAddress(h.config.host),
            "preflight: the target is loopback, private or link-local"
        )
        var refused = false
        do {
            try await NetworkIsolation.requireLocalTarget(h.config.host)
        } catch {
            refused = true
        }
        try h.checks.expect(!refused, "preflight: the shipped isolation check accepts the target")
        try h.checks.expect(
            !NetworkIsolation.isPrivateAddress("203.0.113.10"),
            "preflight: a public address is not classified as local"
        )

        let ping: FixtureReply
        do {
            ping = try await h.transport.get("/rest_api/ping", authorized: false)
        } catch {
            throw E2EFailure(
                "the fixture did not answer at \(h.config.scheme)://\(h.config.authority)/rest_api/ping: \(error)"
            )
        }
        try h.checks.expectEqual(ping.status, 200, "preflight: /rest_api/ping answers with HTTP 200")
        try h.checks.expectEqual(ping.bool("success"), true, "preflight: /rest_api/ping reports success")
        try h.checks.expectEqual(
            ping.bool("simulator"), true,
            "preflight: the peer identifies itself as the simulator fixture"
        )
    }
}

/// The fixture's REST session handshake.
///
/// The shipped `SessionAuthenticator` signs in to the vendor page (`/login.php`
/// with the FW-01 form); the fixture exposes the JSON route `/rest_api/login`
/// instead, so the handshake itself is driven here.  Everything after it is the
/// shipped code: `CookieHeader` parses the `Set-Cookie` header, `VendorSession`
/// is what the clients send, and `LocalAPI` is what the session has to satisfy.
enum SessionSuite {
    /// Sign in and adopt the session, asserting the whole handshake.
    static func signIn(_ h: Harness) async throws {
        // A wrong password first: the fixture must refuse it, and the refusal
        // must not hand out a session.
        let wrong = try await h.transport.post(
            "/rest_api/login",
            json: ["userRole": SimulatorFixture.role, "password": SimulatorFixture.wrongPassword],
            authorized: false
        )
        try h.checks.expectEqual(wrong.status, 400, "login: a wrong password is refused with HTTP 400")
        try h.checks.expect(
            (wrong.string("error") ?? "").contains("invalid simulator credentials"),
            "login: the refusal names the credentials, not the password it was given"
        )
        try h.checks.expect(wrong.setCookie.isEmpty, "login: a refused sign-in hands out no cookie")

        let reply = try await h.transport.post(
            "/rest_api/login",
            json: ["userRole": SimulatorFixture.role, "password": SimulatorFixture.password],
            authorized: false
        )
        try h.checks.expectEqual(reply.status, 200, "login: the fixture accepts the Owner password")
        try h.checks.expectEqual(reply.bool("success"), true, "login: the reply reports success")
        try h.checks.expectEqual(
            reply.string("role"), SimulatorFixture.role,
            "login: the session is an Owner session"
        )
        try h.checks.expectEqual(reply.int("expiresInSeconds"), 900, "login: the session TTL is reported")
        try h.checks.expectEqual(reply.bool("simulator"), true, "login: the reply comes from the fixture")
        try h.checks.expect(
            reply.header("authorization")?.hasPrefix("Bearer ") == true,
            "login: the reply carries the vendor's Authorization: Bearer header"
        )
        try h.checks.expect(
            reply.header("authorization") != "Bearer \(h.config.token)",
            "login: the WSS bearer token is a different credential from the local API token"
        )

        try h.checks.expect(!reply.setCookie.isEmpty, "login: the reply sets a cookie")
        let cookieValue = CookieHeader.sessionCookie(from: reply.setCookie)
        try h.checks.expect(cookieValue != nil, "login: the Set-Cookie header carries a PHPSESSID")
        guard let session = cookieValue.flatMap(VendorSession.init) else {
            throw E2EFailure("login: the fixture's session id is not a plausible PHPSESSID")
        }
        // Registered before it is compared, so neither the verbose line nor a
        // failure detail can print a live session id.
        h.secrets.add(session.sessionID)
        h.secrets.add(session.cookieHeader)
        try h.checks.expectEqual(
            session.cookieHeader,
            "PHPSESSID=\(session.sessionID)",
            "login: the session renders as the one Cookie header the clients send"
        )
        h.adopt(session: session)

        // Both session routes the fixture serves, with the cookie and no token.
        let check = try await h.transport.post(
            "/rest_api/check_session",
            json: [:],
            authorized: false,
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(check.status, 200, "session: check_session accepts the cookie alone")
        try h.checks.expectEqual(
            check.string("role"), SimulatorFixture.role,
            "session: check_session reports the role"
        )

        let update = try await h.transport.post(
            "/rest_api/update_session",
            json: [:],
            authorized: false,
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(update.status, 200, "session: update_session extends the session")
        try h.checks.expectEqual(
            update.bool("success"), true,
            "session: update_session reports success"
        )

        let unauthorised = try await h.transport.post(
            "/rest_api/check_session",
            json: [:],
            authorized: false
        )
        try h.checks.expectEqual(
            unauthorised.status, 401,
            "session: a request without the cookie is refused with HTTP 401"
        )
    }

    /// One sign-in, no assertions: for the places where the handshake is plumbing
    /// rather than the subject.
    @discardableResult
    static func open(_ h: Harness) async throws -> VendorSession {
        let reply = try await h.transport.post(
            "/rest_api/login",
            json: ["userRole": SimulatorFixture.role, "password": SimulatorFixture.password],
            authorized: false
        )
        guard reply.status == 200,
              let value = CookieHeader.sessionCookie(from: reply.setCookie),
              let session = VendorSession(sessionID: value)
        else {
            throw E2EFailure("login: the fixture did not open a session (HTTP \(reply.status))")
        }
        h.adopt(session: session)
        return session
    }

    /// Sign out, prove the session is really gone, and sign back in.
    static func teardown(_ h: Harness) async throws {
        guard let session = h.session else {
            throw E2EFailure("session: no session was established, so none can be ended")
        }
        let logout = try await h.transport.post(
            "/rest_api/logout",
            json: [:],
            authorized: false,
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(logout.status, 200, "logout: the fixture ends the session")
        try h.checks.expectEqual(logout.bool("success"), true, "logout: the reply reports success")
        try h.checks.expect(
            logout.setCookie.contains { $0.contains("PHPSESSID=deleted") },
            "logout: the reply expires the cookie"
        )

        // The fixture's session refusal is a bare `{"error": …}` (HTTP 401), not
        // the module's envelope, so the two halves are asserted separately: the
        // wire says 401, and the client reports the refusal instead of reading it
        // as data.
        let refused = try await h.transport.post(
            "/rest_api/capabilities",
            json: [:],
            cookie: session.cookieHeader
        )
        try h.checks.expectEqual(
            refused.status, 401,
            "logout: the fixture refuses a read on the ended session with HTTP 401"
        )
        try h.checks.expect(
            (refused.string("error") ?? "").lowercased().contains("session"),
            "logout: the refusal names the missing session"
        )
        do {
            _ = try await h.localAPI(token: h.ownerToken, session: session).capabilities()
            throw E2EFailure("logout: a read still succeeded with the ended session")
        } catch let error as APIError {
            h.note(error: error)
            try h.checks.expect(
                isDecodingFailure(error),
                "logout: the session refusal is not the module's envelope, and the client says so instead of yielding data"
            )
        }

        let renewed = try await open(h)
        try h.checks.expect(
            !renewed.sessionID.isEmpty,
            "login: a second sign-in produces a usable session id"
        )
        try h.checks.expect(
            renewed.sessionID != session.sessionID,
            "login: a second sign-in opens a new PHP session"
        )
        let reopened = try await h.localAPI(token: h.ownerToken, session: renewed).capabilities()
        try h.checks.expectEqual(
            reopened.apiVersion, "1",
            "login: the read client works again after signing back in"
        )
    }
}
