import Foundation

/// Executes a `SetupPlan` over the FW-01 login injection.
///
/// This is the Swift port of `tools/e64root/transports.py::WebTransport`:
/// every command is sent as `userRole = "x';<command>;#"` in a
/// `POST /login.php` form, and the root script runs to completion on the
/// device before the response returns.
///
/// Three payloads are transferred:
///   * the **module**, in bounded base64 chunks, appended to
///     `/tmp/e64local.b64`;
///   * the **action runner**, the same way, to `/tmp/e64local-runner.b64`;
///   * the **install script**, base64-encoded in a single request so its
///     quoting cannot collide with the injection's own quoting.
public actor SetupRunner {
    public struct Progress: Sendable {
        public let stage: SetupStage
        public let index: Int
        public let total: Int
        public let message: String

        public init(stage: SetupStage, index: Int, total: Int, message: String) {
            self.stage = stage
            self.index = index
            self.total = total
            self.message = message
        }
    }

    private let transport: Transport
    private let endpoint: Endpoint

    public init(transport: Transport, endpoint: Endpoint) {
        self.transport = transport
        self.endpoint = endpoint
    }

    /// The response of one injected command.
    @discardableResult
    public func inject(command: String, tolerateTimeout: Bool = false) async throws -> TransportResponse {
        let body = FormEncoding.encode(try LoginInjection.formFields(command: command))
        let request = TransportRequest(
            method: "POST",
            url: endpoint.url(path: "/login.php"),
            headers: [
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html, */*;q=0.1",
            ],
            body: Data(body.utf8)
        )
        do {
            return try await transport.send(request)
        } catch {
            // `login.php` runs the injected command synchronously, so a long
            // script can outlive the read timeout after it has already started.
            // Only the final execute step may opt in to that.
            if tolerateTimeout, isTimeout(error) {
                return TransportResponse(status: 0, headers: [:], setCookieHeaders: [], body: Data())
            }
            throw error
        }
    }

    /// Upload `script` and run it as root.  The script is base64-encoded so no
    /// single quote, `;` or `#` in it can interfere with the injection.
    @discardableResult
    public func injectScript(_ script: String, tolerateTimeout: Bool = false) async throws -> TransportResponse {
        let encoded = Data(script.utf8).base64EncodedString()
        let command = "printf '%s' '\(encoded)' | base64 -d > /tmp/e64local-run.sh"
            + " && chmod 700 /tmp/e64local-run.sh"
            + " && sh /tmp/e64local-run.sh"
            + "; rm -f /tmp/e64local-run.sh"
        return try await inject(command: command, tolerateTimeout: tolerateTimeout)
    }

    /// Send the module and the runner in bounded chunks, then run the install
    /// script.
    public func run(
        module: Data,
        runner: Data,
        tokenHex: String,
        chunkSize: Int = SetupPlanner.chunkSize,
        progress: (@Sendable (Progress) -> Void)? = nil
    ) async throws {
        let commands = SetupPlanner.transferCommands(module: module, runner: runner, chunkSize: chunkSize)

        progress?(Progress(stage: .cleanup, index: 0, total: 1, message: "clearing the staging files"))
        try await inject(command: "rm -f \(DevicePaths.stagingBase64) \(DevicePaths.stagingRunnerBase64)")

        for (index, command) in commands.enumerated() {
            progress?(Progress(
                stage: .transfer,
                index: index + 1,
                total: commands.count,
                message: "copying the API module and action runner"
            ))
            try await inject(command: command)
        }

        progress?(Progress(stage: .install, index: 0, total: 1, message: "installing the module and owner token"))
        try await injectScript(
            SetupPlanner.installScript(tokenHex: tokenHex),
            tolerateTimeout: true
        )
    }

    /// Remove the module and its token by running the revert script.
    public func revert(script: String = SetupPlanner.revertScript()) async throws {
        try await injectScript(script, tolerateTimeout: true)
    }

    private func isTimeout(_ error: Error) -> Bool {
        if let transportError = error as? TransportError,
           case .requestFailed(let detail) = transportError {
            return detail.lowercased().contains("timed out")
        }
        return (error as? URLError)?.code == .timedOut
    }
}
