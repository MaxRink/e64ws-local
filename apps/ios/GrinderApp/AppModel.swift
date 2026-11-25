import Combine
import Foundation
import GrinderCore

/// The app's root model.
///
/// One owner, one device, no account.  It holds the device configuration, the
/// owner token (from the Keychain), the vendor session and the data the
/// screens show.  It never mints a WSS credential and never sends a control
/// command.
@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        /// No device configured yet: show Setup.
        case unconfigured
        /// Configured and the local API has answered: show the dashboard.
        case ready
    }

    @Published private(set) var phase: Phase = .unconfigured
    @Published private(set) var configuration: DeviceConfiguration?
    @Published private(set) var capabilities: Capabilities?
    @Published private(set) var machine: Machine?
    @Published private(set) var lastError: String?
    @Published private(set) var isLoading = false

    // Setup screen state.
    @Published var host: String = ""
    @Published var ownerPassword: String = ""
    @Published private(set) var probe: DeviceProbe?
    @Published private(set) var pendingCertificate: CertificateInfo?
    @Published private(set) var setupPlan: SetupPlan?
    @Published private(set) var setupLog: [String] = []
    @Published private(set) var isWorking = false

    private let configurations: ConfigurationStore
    private let tokens: TokenStore
    private var session: VendorSession?
    private var transport: URLSessionTransport?
    private var module: BundledModule?
    private var runner: BundledActionRunner?
    /// The leaf fingerprint the owner accepted on this screen, with the host it
    /// was accepted for.  It survives the probe that clears the *offer*, so the
    /// install runs with the same pin the probe verified.
    private var acceptedPin: (host: String, sha256: String)?

    init(
        configurations: ConfigurationStore? = nil,
        tokens: TokenStore? = nil
    ) {
        let store = configurations ?? FileConfigurationStore()
        self.configurations = store
        self.tokens = tokens ?? Self.defaultTokenStore()
        self.configuration = try? store.load()
        if let configuration, let endpoint = configuration.endpoint {
            self.host = configuration.host
            self.transport = URLSessionTransport(endpoint: endpoint, policy: configuration.trustPolicy)
            self.phase = .ready
        }
    }

    /// The Keychain on device; the in-memory store only when Security is
    /// unavailable (which cannot happen on an iOS device).  Nonisolated because
    /// it only constructs the store.
    private nonisolated static func defaultTokenStore() -> TokenStore {
        #if canImport(Security)
        return KeychainTokenStore()
        #else
        return InMemoryTokenStore()
        #endif
    }

    /// The device host as the endpoint sees it (trimmed, default port omitted),
    /// so the Keychain account and the saved configuration cannot disagree about
    /// the same grinder.
    private var deviceHost: String {
        (try? Endpoint(hostAndPort: host))?.authority ?? host
    }

    private var tokenAccount: String {
        configuration?.host ?? deviceHost
    }

    // MARK: - Setup

    /// Read-only probe: `GET /login.php` and `POST /rest_api/capabilities`.
    func probeDevice() async {
        lastError = nil
        pendingCertificate = nil
        setupPlan = nil
        guard let endpoint = try? Endpoint(hostAndPort: host) else {
            lastError = EndpointError.invalidHostCharacters.errorDescription
            return
        }
        // A pin accepted for a different address does not apply to this one.
        if acceptedPin?.host != endpoint.authority { acceptedPin = nil }
        isWorking = true
        defer { isWorking = false }

        // First attempt uses normal validation; a self-signed device fails
        // here and the owner is offered the explicit opt-in.
        let transport = URLSessionTransport(endpoint: endpoint, policy: .systemDefault)
        var result: Prober.Result?
        do {
            result = try await Prober.probe(endpoint: endpoint, transport: transport)
        } catch {
            lastError = error.localizedDescription
        }

        if case .tlsUntrusted = result?.probe.state, let certificate = transport.observedCertificate {
            pendingCertificate = certificate
        }
        probe = result?.probe
        if let fingerprint = result?.probe.fingerprint {
            setupLog.append("Device: \(fingerprint.model) · \(fingerprint.firmware)")
        }
    }

    /// Opt in to this one device's self-signed certificate and probe again with
    /// the pin in place.  Nothing is trusted that was not shown first.
    func trustPendingCertificate() async {
        guard let certificate = pendingCertificate,
              let endpoint = try? Endpoint(hostAndPort: host)
        else { return }
        isWorking = true
        defer { isWorking = false }

        let transport = URLSessionTransport(
            endpoint: endpoint,
            policy: .pinnedLeaf(sha256: certificate.sha256)
        )
        do {
            let result = try await Prober.probe(endpoint: endpoint, transport: transport)
            probe = result.probe
            // Record the decision, then clear only the offer.  Dropping the pin
            // here would make the install fall back to system validation, which
            // a self-signed device rejects.
            acceptedPin = (endpoint.authority, certificate.sha256)
            pendingCertificate = nil
            setupLog.append("Certificate accepted: \(certificate.sha256.prefix(16))… for this device only")
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Build the one-click plan and show the exact commands.  Generating the
    /// token here means the owner sees the value that will be installed.
    func prepareSetupPlan() async {
        lastError = nil
        guard probe?.canSetup == true else {
            lastError = "The local API is either already installed or cannot be installed on this device."
            return
        }
        do {
            let module = try BundledModule.load()
            let runner = try BundledActionRunner.load()
            // Build the plan before keeping the token: a plan that cannot be
            // built must not leave a token in the Keychain that no device has.
            let token = OwnerToken.generate()
            let plan = try SetupPlanner.installPlan(
                module: module.data,
                runner: runner.data,
                tokenHex: token.value
            )
            try tokens.save(token, for: tokenAccount)
            self.module = module
            self.runner = runner
            setupPlan = plan
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Run the confirmed plan: chunked transfer, then the install script, then
    /// a verified `POST /rest_api/capabilities`.  Success only on a valid
    /// response.
    func runSetup() async {
        lastError = nil
        guard setupPlan != nil, let module, let runner else {
            lastError = "There is no setup plan to run."
            return
        }
        guard let endpoint = try? Endpoint(hostAndPort: host) else {
            lastError = "The grinder address is not valid."
            return
        }
        let token: OwnerToken
        do {
            guard let stored = try tokens.load(for: tokenAccount) else {
                lastError = "The owner token for this grinder is missing from the Keychain. Prepare the setup again."
                return
            }
            token = stored
        } catch {
            lastError = error.localizedDescription
            return
        }
        isWorking = true
        defer { isWorking = false }

        let configuration = DeviceConfiguration(
            host: endpoint.authority,
            pinnedCertificateSHA256: pendingOrExistingPin(for: endpoint),
            trustedAt: Date()
        )
        let transport = URLSessionTransport(endpoint: endpoint, policy: configuration.trustPolicy)
        let installer = SetupRunner(transport: transport, endpoint: endpoint)
        do {
            try await installer.run(module: module.data, runner: runner.data, tokenHex: token.value) { [weak self] progress in
                // The callback is Sendable and runs off the main actor; hop
                // back explicitly to append to the log.
                Task { @MainActor in
                    self?.setupLog.append("\(progress.stage.title) (\(progress.index)/\(progress.total))")
                }
            }
            setupLog.append("Install finished; verifying the handshake…")
            let capabilities = try await activate(
                endpoint: endpoint,
                transport: transport,
                token: token,
                configuration: configuration
            )
            setupLog.append("Verified: Local API v\(capabilities.apiVersion), \(capabilities.routes.count) routes")
            await refreshDashboard()
        } catch {
            lastError = "Setup failed: \(error.localizedDescription)"
            setupLog.append(lastError ?? "")
        }
    }

    /// Sign in to the vendor UI, then prove the installed module with both
    /// factors.  Only a valid `capabilities` document (API version and every
    /// route the app uses) saves the configuration and enters the ready state.
    private func activate(
        endpoint: Endpoint,
        transport: URLSessionTransport,
        token: OwnerToken,
        configuration: DeviceConfiguration
    ) async throws -> Capabilities {
        let authenticator = SessionAuthenticator(transport: transport, endpoint: endpoint)
        let outcome = try await authenticator.signIn(password: ownerPassword)
        guard let session = outcome.session else {
            throw SetupError.verificationFailed(
                "the grinder did not open a vendor session; enter the Owner password and run setup again"
            )
        }
        let api = LocalAPI(
            endpoint: endpoint,
            transport: transport,
            ownerToken: token,
            session: session
        )
        let capabilities = try await api.verifyHandshake()
        try configurations.save(configuration)
        self.session = session
        self.configuration = configuration
        self.transport = transport
        self.capabilities = capabilities
        self.probe = nil
        self.setupPlan = nil
        self.acceptedPin = nil
        self.phase = .ready
        ownerPassword = ""
        return capabilities
    }

    /// True when the module is already on the grinder and this phone holds a
    /// token for it: an interrupted setup only needs the handshake completed.
    var canCompleteSetup: Bool {
        guard probe?.state == .moduleInstalled,
              let endpoint = try? Endpoint(hostAndPort: host)
        else { return false }
        return (try? tokens.load(for: endpoint.authority)) != nil
    }

    /// Finish a setup whose install ran but whose verification did not, without
    /// installing anything again.
    func completeSetup() async {
        lastError = nil
        guard let endpoint = try? Endpoint(hostAndPort: host),
              let token = try? tokens.load(for: endpoint.authority)
        else {
            lastError = "No owner token is stored for this grinder. Prepare the setup again."
            return
        }
        isWorking = true
        defer { isWorking = false }
        let configuration = DeviceConfiguration(
            host: endpoint.authority,
            pinnedCertificateSHA256: pendingOrExistingPin(for: endpoint),
            trustedAt: Date()
        )
        let transport = URLSessionTransport(endpoint: endpoint, policy: configuration.trustPolicy)
        do {
            let capabilities = try await activate(
                endpoint: endpoint,
                transport: transport,
                token: token,
                configuration: configuration
            )
            setupLog.append("Verified: Local API v\(capabilities.apiVersion), \(capabilities.routes.count) routes")
            await refreshDashboard()
        } catch {
            lastError = "Setup could not be verified: \(error.localizedDescription)"
        }
    }

    private func pendingOrExistingPin(for endpoint: Endpoint) -> String? {
        if let acceptedPin, acceptedPin.host == endpoint.authority { return acceptedPin.sha256 }
        if let certificate = pendingCertificate { return certificate.sha256 }
        return configuration?.pinnedCertificateSHA256
    }

    // MARK: - Vendor session

    /// Sign in to the vendor web UI, which the local API routes sit behind.
    func signIn(password: String) async {
        guard let endpoint = configuration?.endpoint ?? (try? Endpoint(hostAndPort: host)),
              let transport
        else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            let authenticator = SessionAuthenticator(transport: transport, endpoint: endpoint)
            let outcome = try await authenticator.signIn(password: password)
            session = outcome.session
            lastError = nil
            await refreshDashboard()
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: - Data

    private func makeAPI() -> LocalAPI? {
        guard let endpoint = configuration?.endpoint ?? (try? Endpoint(hostAndPort: host)),
              let transport
        else { return nil }
        let token = try? tokens.load(for: tokenAccount)
        return LocalAPI(
            endpoint: endpoint,
            transport: transport,
            ownerToken: token ?? nil,
            session: session
        )
    }

    func refreshDashboard() async {
        guard let api = makeAPI() else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            capabilities = try await api.capabilities()
            machine = try await api.machine()
            lastError = nil
        } catch let error as LocalAPIError where session == nil && (error.code == 401 || error.code == 0) {
            // Signed out.  The dispatcher answers an unauthenticated request with
            // `errorCode: 0` ("Access denied!") and the module with 401; the
            // Dashboard offers sign-in, so this is an expected state, not a
            // failure the owner should see in red on every launch.
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func loadLog(_ kind: LogKind, query: LogQuery) async throws -> LogPage {
        guard let api = makeAPI() else { throw AuthError.sessionExpired }
        return try await api.log(kind, query: query)
    }

    func loadRecipes() async throws -> RowTable { try await requireAPI().recipes() }
    func loadPortafilters() async throws -> RowTable { try await requireAPI().portafilters() }
    func loadSettings() async throws -> SettingsExport { try await requireAPI().settings() }
    func loadConfig() async throws -> ConfigExport { try await requireAPI().config() }
    func loadFile(_ path: String) async throws -> FileContent { try await requireAPI().file(path: path) }

    private func requireAPI() throws -> LocalAPI {
        guard let api = makeAPI() else { throw AuthError.sessionExpired }
        return api
    }

    // MARK: - Security

    /// Remove the device, the token and the pin from this phone.  The device
    /// itself is left untouched.
    func forgetDevice(removeFromGrinder: Bool) async {
        isWorking = true
        defer { isWorking = false }
        if removeFromGrinder,
           let endpoint = configuration?.endpoint,
           let transport {
            let runner = SetupRunner(transport: transport, endpoint: endpoint)
            do {
                try await runner.revert()
            } catch {
                lastError = "The local API could not be removed from the grinder: \(error.localizedDescription)"
            }
        }
        // Never report a device as forgotten while its token is still here.
        let account = tokenAccount
        var failures: [String] = []
        do {
            try tokens.delete(for: account)
        } catch {
            failures.append("the owner token is still in the Keychain (\(error.localizedDescription))")
        }
        do {
            try configurations.clear()
        } catch {
            failures.append("the stored device could not be removed (\(error.localizedDescription))")
        }
        guard failures.isEmpty else {
            lastError = "Forget did not finish: " + failures.joined(separator: "; ") + "."
            return
        }
        acceptedPin = nil
        configuration = nil
        capabilities = nil
        machine = nil
        session = nil
        transport = nil
        probe = nil
        phase = .unconfigured
    }

    var hasOwnerToken: Bool {
        (try? tokens.load(for: tokenAccount)) != nil
    }

    var isSessionActive: Bool { session != nil }
}
