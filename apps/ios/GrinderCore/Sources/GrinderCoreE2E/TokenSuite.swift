import Foundation
import GrinderCore

/// The two factors, refused separately.
///
/// Runs last on purpose: the requests here are the only ones in the suite that
/// deliberately leave a factor out, so they must not be in the recording when the
/// "every data request carried both" checks look at it.
enum AuthSuite {
    static func run(_ h: Harness) async throws {
        guard let session = h.session else {
            throw E2EFailure("the session was not established, so the factors cannot be told apart")
        }

        // The session alone is not enough.
        let tokenless = h.localAPI(token: nil, session: session)
        do {
            _ = try await tokenless.capabilities()
            throw E2EFailure("auth: a read without the owner token was answered")
        } catch let error as LocalAPIError {
            h.note(error: error)
            try h.checks.expectEqual(
                error.code, 401,
                "auth: a read with the session but no owner token is refused with errorCode 401"
            )
            try h.checks.expect(
                error.message.lowercased().contains("token"),
                "auth: the refusal names the missing owner token"
            )
        }
        try h.checks.expect(
            h.transport.sentRequests().last?.header(LocalAPI.tokenHeader) == nil,
            "auth: the token-less read really left the header off"
        )

        // The token alone is not enough either.  The fixture's session gate
        // answers a bare `{"error": …}` rather than the module's envelope, so the
        // wire is asserted here and the client's own report below.
        let refused = try await h.transport.post(
            "/rest_api/capabilities",
            json: [:],
            authorized: true,
            cookie: nil
        )
        try h.checks.expectEqual(
            refused.status, 401,
            "auth: a read with the owner token but no session is refused with HTTP 401"
        )
        try h.checks.expect(
            (refused.string("error") ?? "").lowercased().contains("session"),
            "auth: the refusal names the missing session, so the two gates are distinct"
        )
        let sessionless = h.localAPI(token: h.ownerToken, session: nil)
        do {
            _ = try await sessionless.capabilities()
            throw E2EFailure("auth: a read without the vendor session was answered")
        } catch let error as APIError {
            h.note(error: error)
            try h.checks.expect(
                isDecodingFailure(error),
                "auth: the session-less read fails in the client rather than returning data"
            )
        }
        try h.checks.expect(
            h.transport.sentRequests().last?.header(LocalAPI.tokenHeader) == h.config.token,
            "auth: the session-less read still carried the owner token header"
        )

        // The client refuses the two-factor check for verification even earlier.
        do {
            _ = try await sessionless.verifyHandshake()
            throw E2EFailure("auth: verification ran without a session")
        } catch let error as APIError {
            h.note(error: error)
            try h.checks.expect(
                String(describing: error).contains("session"),
                "auth: verifyHandshake refuses to run without both factors"
            )
        }
    }
}

/// The owner token and the session id never reach a log, a body or a URL.
///
/// Reads the recording of everything the suite sent and the list of everything it
/// rendered from failures, so the assertion is about this run's real traffic
/// rather than about a string constant.
enum TokenSuite {
    static func run(_ h: Harness) async throws {
        let requests = h.transport.sentRequests()
        let token = h.config.token

        try h.checks.expect(requests.count >= 20, "token: the suite sent at least twenty requests")

        let inBody = requests.filter { $0.bodyText.contains(token) }
        try h.checks.expect(
            inBody.isEmpty,
            "token: it never appears in a request body (the header is the only carrier)"
        )
        let inURL = requests.filter { $0.url.absoluteString.contains(token) }
        try h.checks.expect(
            inURL.isEmpty,
            "token: it never appears in a request URL"
        )

        let carried = requests.filter { $0.header(LocalAPI.tokenHeader) != nil }
        try h.checks.expect(
            carried.count >= 15,
            "token: at least fifteen requests carried it in the owner-token header"
        )
        try h.checks.expect(
            carried.allSatisfy { $0.header(LocalAPI.tokenHeader) == token },
            "token: every request that carried a token carried the harness one, and nothing else"
        )

        // Nothing the suite rendered from a failure carries a secret.
        try h.checks.expect(!h.renderedText.isEmpty, "token: the suite recorded the errors it rendered")
        let renderedWithToken = h.renderedText.filter { $0.contains(token) }
        try h.checks.expect(
            renderedWithToken.isEmpty,
            "token: no rendered error contains it"
        )
        guard let session = h.session else {
            throw E2EFailure("token: no session was established, so its description cannot be checked")
        }
        try h.checks.expect(
            !h.renderedText.contains { $0.contains(session.sessionID) },
            "token: no rendered error contains the session id"
        )

        // The types that could be printed are redacted.
        try h.checks.expect(
            !String(describing: h.ownerToken).contains(h.ownerToken.value),
            "token: OwnerToken's description withholds its value"
        )
        try h.checks.expect(
            String(describing: h.ownerToken).contains("withheld"),
            "token: OwnerToken's description says the value is withheld"
        )
        try h.checks.expect(
            !String(describing: session).contains(session.sessionID),
            "token: VendorSession's description withholds the session id"
        )
        try h.checks.expect(
            String(describing: session).contains("withheld"),
            "token: VendorSession's description says the session id is withheld"
        )

        // The shipped redactor catches a secret-shaped line, and the harness's own
        // output scrubber — what the verbose lines and the FAIL line go through —
        // removes the token and the session id.
        try h.checks.expect(
            LogRedaction.looksSecret("password=\(SimulatorFixture.password)"),
            "token: the shipped redactor recognises a password line"
        )
        try h.checks.expect(
            !LogRedaction.redact("token=\(token)").contains(token),
            "token: the shipped redactor removes the token from a log line"
        )
        try h.checks.expect(
            !h.secrets.hide("X-E64-Local-Token: \(token)").contains(token),
            "token: the harness's output scrubber removes it from a line"
        )
        try h.checks.expect(
            !h.secrets.hide("Cookie: \(session.cookieHeader)").contains(session.sessionID),
            "token: the harness's output scrubber removes the session id"
        )
    }
}
