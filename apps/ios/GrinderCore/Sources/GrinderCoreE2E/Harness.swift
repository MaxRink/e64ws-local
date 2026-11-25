import Foundation
import GrinderCore

/// The values `tools/e64ws_simulator.py` serves.  They are fixture constants, not
/// device behaviour: every one of them is documented in the simulator's own
/// source or in `docs/LOCAL_API.md` §14.
enum SimulatorFixture {
    /// `SimulatedAuth.login` accepts these four roles with the fixture password.
    static let role = "Owner"
    /// `SimulatedAuth.password` — the fixture's documented test value.
    static let password = "sim-password"
    static let wrongPassword = "not-the-fixture-password"

    /// `SimulatedLocalApi.serial` — returned only as a SHA-256.
    static let serialNumber = "SIM0000000001"
    /// `SimulatedGrinder.firmware_build`.
    static let firmware = "V01.16-24-mock"
    /// `SimulatedLocalApi.GRINDER_TYPE_NAMES[5]`.
    static let model = "E64 WS"
    static let variant = "Hsg"

    /// Values the fixture seeds into its log rows and must never return raw.
    static let wifiSecret = "sim-wifi-secret"
    static let wifiAddress = "192.168.77.23"
    static let logSecret = "sim-log-secret"

    /// `SimulatedLocalApi.ROUTES` — the eleven read routes.
    static let readRoutes: Set<String> = [
        "alert_log", "capabilities", "config", "file", "grind_log", "machine",
        "portafilters", "recipes", "service_log", "settings", "ws_token",
    ]

    /// Keys `redact_settings` withholds from the fixture's settings map.
    static let redactedSettingKeys: Set<String> = [
        "Role.Owner.LoginData", "Role.Technician.LoginData", "Role.Barista.LoginData",
        "Wifi.StaPassword", "M2m.CoffeeMachinesConfig", "productionWifiSsid",
    ]

    /// Paths `redact_config` replaces inside the fixture's config document.
    static let redactedConfigPaths: Set<String> = [
        "grinderSn", "productionWifiSsid", "productionWifiPassword", "cloudBaseUrl",
    ]

    /// `ActionEngine.gate_reason()` while no policy file is installed.
    static let gateReason = "actions are not enabled (policy file missing)"
    /// `ActionEngine.capabilities()`'s `blocked` text for a destructive entry.
    static let destructiveBlocked = "destructive actions are disabled"

    /// The five meta routes as the fixture serves them
    /// (`SimulatedLocalApi.ACTION_ROUTES`).
    static let actionMetaRoutes: Set<String> = [
        "action_prepare", "action_execute", "action_status", "action_cancel", "action_audit",
    ]

    /// `len(ACTION_CATALOG)` and its split, from `tools/e64local_actions.py`.
    /// Eight of the 33 entries are unavailable and one of those
    /// (`action_factory_reset`) is in the destructive risk class without being
    /// flagged destructive, so 25 implemented minus 7 flagged leaves 18 that a
    /// gate with the destructive second gate closed may advertise.
    static let catalogEntries = 33
    static let implementedEntries = 25
    static let unavailableEntries = 8
    static let destructiveEntries = 7
    static let destructiveRiskClassEntries = 8
    static let dispatchableWhenOpen = 18

    /// A non-destructive actuator that takes no parameters: the happy path.
    static let stopRoute = "action_grind_stop"
    /// A second parameterless actuator, used for cancel-before-execute.
    static let cancelRoute = "action_agsa_stop"
    /// A destructive route the second gate must refuse.
    static let destructiveRoute = "action_logs_clear"
}

/// The suite's shared state: one transport, one assertion counter, one session.
///
/// The order of `run()` is the order the checks read best in: reachability, the
/// session handshake, the read routes, the action surface, teardown, the two
/// negative authentication probes, and finally the token-hygiene pass over
/// everything that was rendered or sent.
final class Harness: @unchecked Sendable {
    let config: E2EConfig
    let transport: FixtureTransport
    let checks: Checks
    let secrets: SecretRegistry
    let endpoint: Endpoint
    /// What the clients hold.  On the fixture this is a stand-in: `OwnerToken`
    /// accepts only the 64 hex characters a device writes, and the fixture's
    /// token is not one, so `FixtureTransport` is what puts the real fixture
    /// credential on the wire.
    let ownerToken: OwnerToken

    private(set) var session: VendorSession?
    /// Every string this suite rendered from a failure, so the token checks can
    /// assert that none of them carries a secret.
    private(set) var renderedText: [String] = []

    init(config: E2EConfig, checks: Checks, secrets: SecretRegistry) throws {
        self.config = config
        self.transport = FixtureTransport(baseURL: config.baseURL, token: config.token)
        self.checks = checks
        self.secrets = secrets
        do {
            self.endpoint = try Endpoint(host: config.host, port: config.port)
        } catch {
            throw E2EFailure(
                "\(E2EConfig.baseURLKey) is not a host and port the clients accept: \(error)"
            )
        }
        self.ownerToken = OwnerToken(value: config.token) ?? OwnerToken.generate()
    }

    /// True when the harness token is not the shape a device writes.
    var usesStandInOwnerToken: Bool { ownerToken.value != config.token }

    func adopt(session: VendorSession) {
        self.session = session
        secrets.add(session.sessionID)
        secrets.add(session.cookieHeader)
    }

    /// Record everything about a failure that could conceivably be printed.
    func note(error: Error) {
        renderedText.append(String(describing: error))
        if let localized = (error as? LocalizedError)?.errorDescription {
            renderedText.append(localized)
        }
    }

    func localAPI(token: OwnerToken?, session: VendorSession?) -> LocalAPI {
        LocalAPI(endpoint: endpoint, transport: transport, ownerToken: token, session: session)
    }

    func run() async throws {
        try await PreflightSuite.run(self)
        try await SessionSuite.signIn(self)
        let capabilities = try await ReadSuite.run(self)
        try await ActionSuite.run(self, capabilities: capabilities)
        try await SessionSuite.teardown(self)
        try await AuthSuite.run(self)
        try await TokenSuite.run(self)
    }
}

/// True for `APIError.decodingFailed`: how the client reports a body that is not
/// the module's envelope.  The fixture's session refusal is one of those, which is
/// a real difference between the fixture and `ondevice/rest_api_dev.php` — the
/// module answers every handled failure with `success`/`errorCode`, the fixture's
/// session gate answers `{"error": …}` alone.
func isDecodingFailure(_ error: APIError) -> Bool {
    if case .decodingFailed = error { return true }
    return false
}
