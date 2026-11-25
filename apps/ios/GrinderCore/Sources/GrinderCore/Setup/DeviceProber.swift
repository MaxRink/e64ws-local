import Foundation

/// What the setup screen reports about a device before anything is changed.
public struct DeviceProbe: Sendable {
    public enum State: Equatable, Sendable {
        /// The device answered `GET /login.php` and looks like an E64 WS / NG2.
        case reachable
        /// The device answered but is not a grinder this app knows.
        case notAGrinder(String)
        /// The local API module is already installed (its `capabilities` route
        /// demanded an owner token).
        case moduleInstalled
        /// The local API module is missing; one-click setup can install it.
        case moduleMissing
        /// The module answered directly with a dev-gate refusal: the image is
        /// not a development image, so nothing can be installed here.
        case notDevelopmentImage
        /// TLS validation failed and the owner has not opted in yet.
        case tlsUntrusted(String)
        case unreachable(String)
    }

    public struct Fingerprint: Equatable, Sendable {
        public let model: String
        public let firmware: String
        public let devMode: Bool
        public let title: String

        public init(model: String, firmware: String, devMode: Bool, title: String) {
            self.model = model
            self.firmware = firmware
            self.devMode = devMode
            self.title = title
        }
    }

    public let state: State
    public let fingerprint: Fingerprint?
    /// The leaf certificate seen while probing, offered for explicit opt-in.
    public let certificate: CertificateInfo?

    public init(state: State, fingerprint: Fingerprint? = nil, certificate: CertificateInfo? = nil) {
        self.state = state
        self.fingerprint = fingerprint
        self.certificate = certificate
    }

    /// `true` when one-click setup is offered for this device.
    public var canSetup: Bool {
        switch state {
        case .moduleMissing: return true
        default: return false
        }
    }
}

/// Reads the facts the setup screen needs, without changing the device.
///
/// Two probes, both read-only:
///   * `GET /login.php` — the vendor login page identifies the model, firmware
///     and whether the image is a development image (`isDev()`, which adds the
///     `Developer` role option).  This is the pre-shell dev-mode signal.
///   * `POST /rest_api/capabilities` — the module's own answer tells us whether
///     it is installed: `errorCode: 401` means it is present and demanding the
///     owner token, and a direct `403` is the dev-gate refusal. Every other
///     envelope is the vendor dispatcher answering instead of the module, so the
///     module is missing. The capabilities probe must carry the `PHPSESSID` from
///     the login page: the dispatcher checks the session first and answers an
///     unauthenticated request with `console: "Access denied!"` and
///     `errorCode: 0`, which would make a missing module look installed.
public enum Prober {
    public struct Result: Sendable {
        public let probe: DeviceProbe
        public let session: VendorSession?
    }

    public static func probe(
        endpoint: Endpoint,
        transport: Transport
    ) async throws -> Result {
        // 1. The vendor login page.  This handshake also captures the leaf
        //    certificate, so even a refused TLS trust can still be shown to the
        //    owner for an explicit opt-in.
        let loginResponse: TransportResponse
        do {
            loginResponse = try await transport.send(
                TransportRequest(
                    method: "GET",
                    url: endpoint.url(path: "/login.php"),
                    headers: ["Accept": "text/html, */*;q=0.1"]
                )
            )
        } catch let error as TransportError {
            let certificate = certificate(from: transport)
            var state = classify(error)
            // A TLS refusal is where the certificate matters; a missing one
            // (the handshake never completed) leaves the owner with the plain
            // message.
            if case .tlsUntrusted = state, certificate == nil {
                state = .unreachable(error.errorDescription ?? "TLS failure")
            }
            return Result(probe: DeviceProbe(state: state, certificate: certificate), session: nil)
        } catch {
            return Result(
                probe: DeviceProbe(
                    state: .unreachable(error.localizedDescription),
                    certificate: certificate(from: transport)
                ),
                session: nil
            )
        }

        let fingerprint = parseLoginPage(loginResponse.text)
        let session = CookieHeader.sessionCookie(from: loginResponse.setCookieHeaders)
            .flatMap(VendorSession.init)

        // 2. The local API handshake, with the vendor session and no owner
        //    token.  The cookie matters: the dispatcher rejects an
        //    unauthenticated request before it reaches the module, and that
        //    rejection is shaped like a missing module (both carry
        //    `errorCode: 0`).
        var probeHeaders = [
            "Content-Type": "application/json",
            "Accept": "application/json",
        ]
        if let session { probeHeaders["Cookie"] = session.cookieHeader }
        let capabilities: TransportResponse?
        do {
            capabilities = try await transport.send(
                TransportRequest(
                    method: "POST",
                    url: endpoint.url(path: "/rest_api/capabilities"),
                    headers: probeHeaders,
                    body: Data("{}".utf8)
                )
            )
        } catch {
            capabilities = nil
        }

        let state = classify(
            loginStatus: loginResponse.status,
            fingerprint: fingerprint,
            capabilities: capabilities
        )
        return Result(
            probe: DeviceProbe(
                state: state,
                fingerprint: fingerprint,
                certificate: certificate(from: transport)
            ),
            session: session
        )
    }

    /// Classify the capabilities answer.  Public so the setup logic is
    /// exercised directly by the checks.
    public static func classify(
        loginStatus: Int,
        fingerprint: DeviceProbe.Fingerprint?,
        capabilities: TransportResponse?
    ) -> DeviceProbe.State {
        guard loginStatus == 200 || loginStatus == 302 else {
            return .notAGrinder("GET /login.php returned HTTP \(loginStatus)")
        }
        // `parseLoginPage` returns nil for anything without the Hemro markers,
        // so a non-nil fingerprint is what makes this a grinder.
        guard fingerprint != nil else {
            return .notAGrinder("the login page did not identify a grinder")
        }

        guard let capabilities else {
            return .moduleMissing
        }
        guard let envelope = try? JSONDecoder().decode(Envelope<AnyCodable2>.self, from: capabilities.body) else {
            // No JSON envelope: an HTML page or a proxy error, not the module.
            return .moduleMissing
        }
        if envelope.success {
            // The module answered its own capabilities document.
            return .moduleInstalled
        }
        switch envelope.errorCode {
        case 401:
            // The module was reached and demanded the owner token.
            return .moduleInstalled
        case 403:
            // A direct 403 with `success: false` is the dev gate.
            return .notDevelopmentImage
        default:
            // The vendor dispatcher answered instead of the module: an unknown
            // route ("Error, unknown REST command", errorCode 0) or an
            // unauthenticated refusal.  Either way the module is not installed.
            return .moduleMissing
        }
    }

    public static func classify(_ error: TransportError) -> DeviceProbe.State {
        switch error {
        case .tlsRejected(let detail):
            return .tlsUntrusted(detail)
        case .notLocal(let reason):
            return .unreachable(reason.errorDescription ?? "not a local address")
        case .requestFailed(let detail):
            return .unreachable(detail)
        case .redirectRefused(let location):
            return .unreachable("redirected to \(location)")
        case .notHTTP:
            return .unreachable("non-HTTP response")
        case .notThisDevice(let url):
            return .unreachable("the app refused a request outside the configured grinder (\(url))")
        }
    }

    /// Read model, firmware and dev mode from the unauthenticated login page,
    /// following the markers `tools/e64root/target.py::parse_login_page` uses.
    public static func parseLoginPage(_ html: String) -> DeviceProbe.Fingerprint? {
        guard !html.isEmpty else { return nil }
        let title = firstMatch(in: html, pattern: "<title>\\s*Login\\s+Hemro\\s*([^<]+?)\\s*</title>")
            ?? ""
        let model = labelValue(in: html, label: "MODEL")
        let firmware = labelValue(in: html, label: "FW VERSION")
        let hasDeveloperOption = html.range(
            of: "<option[^>]+value=[\"']Developer[\"']", options: .regularExpression
        ) != nil
        let devMode = html.range(of: "\\(development\\)", options: .regularExpression) != nil
            || hasDeveloperOption

        if title.isEmpty && firmware.isEmpty { return nil }
        return DeviceProbe.Fingerprint(
            model: model.trimmingCharacters(in: .whitespaces),
            firmware: firmware.trimmingCharacters(in: .whitespaces),
            devMode: devMode,
            title: title.trimmingCharacters(in: .whitespaces)
        )
    }

    /// `>\s*LABEL</div>\s*<div…>\s*VALUE</div>`, as the vendor page renders it.
    private static func labelValue(in html: String, label: String) -> String {
        let pattern = ">\\s*\(NSRegularExpression.escapedPattern(for: label))\\s*</div>"
            + "\\s*<div[^>]*>\\s*([^<]*?)\\s*</div>"
        return firstMatch(in: html, pattern: pattern)?.trimmingCharacters(in: .whitespaces) ?? ""
    }

    private static func firstMatch(in text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators]) else {
            return nil
        }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, options: [], range: range),
              match.numberOfRanges > 1,
              let capture = Range(match.range(at: 1), in: text)
        else {
            return nil
        }
        return String(text[capture])
    }

    private static func certificate(from transport: Transport) -> CertificateInfo? {
        (transport as? URLSessionTransport)?.observedCertificate
    }
}
