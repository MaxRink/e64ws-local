import Foundation
import GrinderCore

// MARK: - Log query

func logQueryChecks() -> [CheckCase] {
    [
        CheckCase("query: limits are clamped to the documented range") {
            try checkEqual(try LogQuery(limit: 0).limit, 1)
            try checkEqual(try LogQuery(limit: 99_999).limit, 5000)
            try checkEqual(try LogQuery(offset: -5).offset, 0)
            try checkEqual(try LogQuery(offset: 9_000_000).offset, 1_000_000)
        },
        CheckCase("query: accepted filter forms") {
            for value in ["2026-01-01", "2026-01-01 12:00:00", "2026-01-01T12:00:00", "1767225600"] {
                _ = try LogQuery(since: value)
            }
            try checkEqual(try LogQuery(since: "  ").since, nil)
        },
        CheckCase("query: malformed filters are refused before sending") {
            for value in ["yesterday", "2026-13-01", "2026-01-01 25:00:00", "2026-01-01 12:00", "01-01-2026"] {
                var threw = false
                do { _ = try LogQuery(since: value) } catch { threw = true }
                try check(threw, "\(value) should be rejected")
            }
        },
        CheckCase("query: since after until is refused") {
            var threw = false
            do { _ = try LogQuery(since: "2026-02-01", until: "2026-01-01") } catch { threw = true }
            try check(threw, "inverted range must be rejected")
            _ = try LogQuery(since: "2026-01-01", until: "2026-01-01")
        },
    ]
}

// MARK: - File allowlist

func fileAllowlistChecks() -> [CheckCase] {
    [
        CheckCase("file: the exact allowlist paths are accepted") {
            for path in ["/etc/issue", "/tmp/FirmwareUpdateState.json", "/log/messages"] {
                try check(FileAllowlist.isAllowed(path), "\(path) should be allowed")
            }
        },
        CheckCase("file: anything outside the allowlist is refused client-side") {
            for path in [
                "/db/HsgSqlite.db", "/db/e64local/token", "/etc/shadow", "/etc/passwd",
                "/log/../db/HsgSqlite.db", "/logfoo/messages", "/proc/self/environ",
                "/log/", "log/messages", "/log/.hidden", "/log/sub/file",
                "/etc/issue\0", "", "/sys/kernel",
            ] {
                try check(!FileAllowlist.isAllowed(path), "\(path) should be refused")
            }
        },
        CheckCase("file: base64 and text content both decode to bytes") {
            let text = try JSONDecoder().decode(
                FileContent.self,
                from: Data(#"{"path":"/etc/issue","encoding":"text","content":"development image"}"#.utf8)
            )
            try checkEqual(text.bytes, Data("development image".utf8))
            let binary = try JSONDecoder().decode(
                FileContent.self,
                from: Data(#"{"path":"/log/blob.bin","encoding":"base64","content":"AAH/YmluYXJ5"}"#.utf8)
            )
            try checkEqual(binary.bytes?.count, 9)
        },
    ]
}

// MARK: - Bundled module

func moduleChecks() -> [CheckCase] {
    let expected = "ca0203d6cee4e0ec241fe37e27ca0d17178def082d103feb774d7ddf93ea4c0c"
    let expectedRunner = "a6f3ec2ac191e0d13094a221551590041c38b90b7624fb102d8874ad283cb35b"

    return [
        CheckCase("module: the bundled module matches the pinned SHA-256") {
            let module = try BundledModule.load()
            try checkEqual(Fingerprints.sha256Hex(module.data), expected, "bundled digest")
            try checkEqual(BundledModule.expectedSHA256, expected, "pinned digest")
        },
        CheckCase("module: the bundled copy equals the repository copy byte for byte") {
            let module = try BundledModule.load()
            let repositoryCopy = URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent() // GrinderCoreChecksKit
                .deletingLastPathComponent() // Sources
                .deletingLastPathComponent() // GrinderCore
                .deletingLastPathComponent() // apps/ios
                .deletingLastPathComponent() // apps
                .deletingLastPathComponent() // repository root
                .appendingPathComponent("ondevice/rest_api_dev.php")
            guard FileManager.default.fileExists(atPath: repositoryCopy.path) else {
                // Running outside a checkout (for example a built product):
                // the pinned SHA-256 above already covers this case.
                return
            }
            let source = try Data(contentsOf: repositoryCopy)
            try checkEqual(Fingerprints.sha256Hex(source), expected, "repository digest")
            try checkEqual(module.data, source, "bytes")
        },
        CheckCase("module: a tampered module is refused") {
            var tampered = try BundledModule.load().data
            tampered.append(0x0A)
            var threw = false
            do {
                let url = FileManager.default.temporaryDirectory
                    .appendingPathComponent("tampered-\(UUID().uuidString).php")
                try tampered.write(to: url)
                defer { try? FileManager.default.removeItem(at: url) }
                _ = try BundledModule.load(contentsOf: url)
            } catch { threw = true }
            try check(threw, "a digest mismatch must throw")
        },
        CheckCase("module: it declares the dev gate and the token file it relies on") {
            let text = try checkNotNil(String(data: try BundledModule.load().data, encoding: .utf8))
            try check(text.contains("isDev()"), "dev gate")
            try check(text.contains("/db/e64local/token"), "token path")
            try check(text.contains("X_E64_LOCAL_TOKEN"), "owner token header")
            try check(text.contains("/db/e64local/actions.json"), "action gate policy path")
            try check(
                text.contains("actions are not enabled (policy file missing)"),
                "actions fail closed without a policy"
            )
        },
        CheckCase("module: the bundled action runner matches the pinned SHA-256") {
            let runner = try BundledActionRunner.load()
            try checkEqual(Fingerprints.sha256Hex(runner.data), expectedRunner, "bundled runner digest")
            try checkEqual(BundledActionRunner.expectedSHA256, expectedRunner, "pinned runner digest")
            let copy = repositoryRoot().appendingPathComponent("ondevice/e64local_action_run.php")
            if FileManager.default.fileExists(atPath: copy.path) {
                try checkEqual(runner.data, try Data(contentsOf: copy), "runner bytes")
            }
        },
        CheckCase("module: the install installs the runner but no action policy") {
            let script = SetupPlanner.installScript(tokenHex: String(repeating: "0", count: 64))
            try check(script.contains("/usr/local/bin/e64local-action-run"), "runner path")
            try check(!script.contains("> /db/e64local/actions.json"), "no policy file")
            let plan = try SetupPlanner.installPlan(
                module: Data("m".utf8),
                runner: Data("r".utf8),
                tokenHex: String(repeating: "0", count: 64)
            )
            try check(
                plan.notes.contains { $0.contains("action route stays disabled") },
                "the plan states that actions stay disabled"
            )
        },
    ]
}

// MARK: - Setup protocol (FW-01)

func setupChecks() -> [CheckCase] {
    let tokenHex = String(repeating: "0123456789abcdef", count: 4)
    let runnerBytes = Data(repeating: 0x52, count: 900)

    return [
        CheckCase("setup: the injection closes the quote and comments the tail") {
            try checkEqual(try LoginInjection.userRole(command: "id"), "x';id;#")
            var threw = false
            do { _ = try LoginInjection.userRole(command: "id\0") } catch { threw = true }
            try check(threw, "a NUL byte must be refused")
        },
        CheckCase("setup: the login form is exactly the e64root shape") {
            let fields = try LoginInjection.formFields(command: "id")
            try checkEqual(fields.map(\.name), ["login", "requestDeveloper", "password", "userRole"])
            try checkEqual(fields[0].value, "1")
            try checkEqual(fields[1].value, "1")
            try checkEqual(fields[3].value, "x';id;#")
        },
        CheckCase("setup: both payloads are chunked at 40000 characters like WEB_CHUNK") {
            let module = Data(repeating: 0x41, count: 60_000)
            let runner = Data(repeating: 0x52, count: 1_000)
            let commands = SetupPlanner.transferCommands(module: module, runner: runner)
            try checkEqual(commands.count, 3, "two module chunks and one runner chunk")

            func payloads(appendingTo staging: String) -> [String] {
                commands.filter { $0.hasSuffix(">> \(staging)") }.compactMap { command in
                    guard let start = command.range(of: "printf '%s' '"),
                          let end = command.range(of: "' >> ", range: start.upperBound..<command.endIndex)
                    else { return nil }
                    return String(command[start.upperBound..<end.lowerBound])
                }
            }
            let modulePayloads = payloads(appendingTo: DevicePaths.stagingBase64)
            let runnerPayloads = payloads(appendingTo: DevicePaths.stagingRunnerBase64)
            try checkEqual(modulePayloads.count, 2, "module chunks")
            try checkEqual(modulePayloads[0].count, 40_000, "first module chunk size")
            try checkEqual(Data(base64Encoded: modulePayloads.joined()), module, "module reassembles")
            try checkEqual(runnerPayloads.count, 1, "runner chunks")
            try checkEqual(Data(base64Encoded: runnerPayloads.joined()), runner, "runner reassembles")
            for command in commands {
                try check(command.contains("printf '%s' '"), "printf form")
            }
        },
        CheckCase("setup: a token of the wrong length is refused") {
            var threw = false
            do {
                _ = try SetupPlanner.installPlan(module: Data("x".utf8), runner: Data("r".utf8), tokenHex: "short")
            } catch { threw = true }
            try check(threw, "a short token must be refused")
            threw = false
            do {
                _ = try SetupPlanner.installPlan(
                    module: Data("x".utf8),
                    runner: Data("r".utf8),
                    tokenHex: String(repeating: "A", count: 64)
                )
            } catch { threw = true }
            try check(threw, "an uppercase token must be refused")
        },
        CheckCase("setup: the install script installs the module and the owner token with the right modes") {
            let script = SetupPlanner.installScript(tokenHex: tokenHex)
            try check(script.contains("/usr/local/www/dev/rest_api_dev.php"), "module path")
            try check(script.contains("chmod 644 /usr/local/www/dev/rest_api_dev.php"), "module mode")
            try check(script.contains("mkdir -p /db/e64local"), "token directory")
            try check(script.contains("chmod 711 /db/e64local"), "token directory mode")
            try check(script.contains("/db/e64local/token"), "token path")
            try check(script.contains("chmod 600 /db/e64local/token"), "token mode")
            try check(script.contains("chown www-data:www-data"), "token owner")
            try check(script.contains("'\(tokenHex)'"), "token value")
            try check(script.contains("mkdir -p /usr/local/www/dev"), "creates the module directory")
            try check(script.contains("base64 -d /tmp/e64local.b64"), "decodes the module staging file")
            try check(script.contains("base64 -d /tmp/e64local-runner.b64"), "decodes the runner staging file")
            try check(script.contains("chmod 755 /usr/local/bin/e64local-action-run"), "runner mode")
            try check(script.contains("chown root:root /usr/local/bin/e64local-action-run"), "runner owner")
            try check(script.contains("php -l /usr/local/bin/e64local-action-run"), "runner is validated")
            try check(!script.contains("> /db/e64local/actions.json"), "no action policy is written")
            try check(
                script.contains("rm -f /tmp/e64local.b64 /tmp/e64local-runner.b64"),
                "removes both staging files"
            )
        },
        CheckCase("setup: the install script never touches the ESP, firmware, NVS, bootloader or eFuse") {
            let forbidden = [
                "ttySTM5", "upload_esp", "flashEspZip", "setEspBootmode", "firmware", "esptool",
                "nvs", "bootloader", "efuse", "otp", "swu", "reboot", "dd if=", "mtd",
            ]
            let script = SetupPlanner.installScript(tokenHex: tokenHex).lowercased()
            for word in forbidden {
                try check(!script.contains(word.lowercased()), "install script mentions \(word)")
            }
        },
        CheckCase("setup: the revert script removes only the module and the token") {
            let script = SetupPlanner.revertScript()
            try check(script.contains("rm -f /usr/local/www/dev/rest_api_dev.php"), "module removed")
            try check(script.contains("rm -f /db/e64local/token"), "token removed")
            try check(!script.lowercased().contains("rm -rf"), "no recursive delete")
            try check(!script.contains("/db/HsgSqlite.db"), "the database is never touched")
        },
        CheckCase("setup: the shown plan hides the owner token but the sent script has it") {
            let module = Data(repeating: 0x42, count: 45_000)
            let plan = try SetupPlanner.installPlan(module: module, runner: runnerBytes, tokenHex: tokenHex)
            let rendered = plan.render()
            try checkEqual(plan.chunkCount, 3, "two module chunks and one runner chunk")
            try check(plan.script.contains("'\(tokenHex)'"), "the script that runs carries the token")
            try check(!plan.displayScript.contains(tokenHex), "the shown script must not carry the token")
            try check(
                plan.displayScript.contains("generated on this phone"),
                "the placeholder explains what is hidden"
            )
            try check(!rendered.contains(tokenHex), "the rendered plan must not carry the token")
            try check(rendered.contains("Shell script executed on the grinder"), "script heading")
            try check(rendered.contains("Notes:"), "notes")
            // Each displayed chunk is clipped, so the plan a person reads is
            // never wider than a phone screen.  The sent values are untouched.
            let longestLine = rendered.split(separator: "\n").map(\.count).max() ?? 0
            try check(longestLine < 1200, "displayed chunk should be truncated, longest line \(longestLine)")
            try checkEqual(plan.chunks.count, 3, "every chunk is listed")
            try check(plan.chunks[0].count < 600, "a displayed chunk is clipped")
            let sent = SetupPlanner.transferCommands(module: module, runner: runnerBytes).first ?? ""
            try check(sent.contains("printf '%s' '"), "the sent command is the real one")
            try check(sent.contains("'\(module.base64EncodedString().prefix(100))"), "the sent chunk is not clipped")
        },
        CheckCase("setup: a full run sends cleanup, chunks, then the install, and nothing else") {
            let stub = StubTransport(responses: [
                "login.php": jsonResponse("<html></html>"),
            ])
            let endpoint = try Endpoint(host: "192.168.1.100")
            let installer = SetupRunner(transport: stub, endpoint: endpoint)
            let module = Data(repeating: 0x43, count: 50_000)
            let runnerFile = Data(repeating: 0x54, count: 900)
            try await installer.run(
                module: module,
                runner: runnerFile,
                tokenHex: tokenHex,
                chunkSize: 40_000
            )
            let requests = await stub.requests
            try checkEqual(requests.count, 1 + 2 + 1 + 1, "cleanup + module chunks + runner chunk + install")
            let stagedRunner = requests.contains { request in
                let body = request.body.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                return (body.removingPercentEncoding ?? body).contains("/tmp/e64local-runner.b64")
            }
            try check(stagedRunner, "the runner is staged")
            try check(requests.allSatisfy { $0.url.path == "/login.php" }, "only login.php is contacted")
            try checkEqual(requests.first?.method, "POST")
            // Every request is a form whose userRole carries the injected command.
            for request in requests {
                let body = try checkNotNil(String(data: request.body ?? Data(), encoding: .utf8))
                try check(body.contains("userRole=x%27%3B"), "userRole injection present")
            }
        },
        CheckCase("setup: the install script is uploaded and run, never decoded from the module") {
            let stub = StubTransport(responses: ["login.php": jsonResponse("<html></html>")])
            let endpoint = try Endpoint(host: "192.168.1.100")
            let installer = SetupRunner(transport: stub, endpoint: endpoint)
            try await installer.run(
                module: Data(repeating: 0x44, count: 1_000),
                runner: Data(repeating: 0x55, count: 300),
                tokenHex: tokenHex
            )
            let requests = await stub.requests
            let last = try checkNotNil(requests.last, "install request")
            let body = try checkNotNil(String(data: last.body ?? Data(), encoding: .utf8))
            let decoded = body.removingPercentEncoding ?? body

            let script = SetupPlanner.installScript(tokenHex: tokenHex)
            let encoded = Data(script.utf8).base64EncodedString()
            try check(decoded.contains(encoded), "the install script is sent, base64-encoded")
            try check(decoded.contains("/tmp/e64local-run.sh"), "it runs from its own file")
            try check(!decoded.contains("/tmp/e64local-install.sh"), "no file is decoded from the module staging path")

            // Decode the payload exactly as the device does and check the script.
            guard let start = decoded.range(of: "printf '%s' '"),
                  let end = decoded.range(of: "' | base64 -d", range: start.upperBound..<decoded.endIndex),
                  let uploaded = Data(base64Encoded: String(decoded[start.upperBound..<end.lowerBound]))
            else {
                throw CheckFailure(message: "cannot find the uploaded payload", file: #filePath, line: #line)
            }
            let uploadedScript = try checkNotNil(String(data: uploaded, encoding: .utf8), "uploaded script")
            try checkEqual(uploadedScript, script, "the device receives exactly the shown script")
            try check(uploadedScript.contains("base64 -d /tmp/e64local.b64"), "the script decodes the module itself")
        },
        CheckCase("setup: the revert runs a base64-encoded script, not a quoted one") {
            let stub = StubTransport(responses: ["login.php": jsonResponse("<html></html>")])
            let endpoint = try Endpoint(host: "192.168.1.100")
            let runner = SetupRunner(transport: stub, endpoint: endpoint)
            try await runner.revert()
            let request = try checkNotNil(await stub.requests.first, "revert request")
            let body = try checkNotNil(String(data: request.body ?? Data(), encoding: .utf8))
            let decoded = body.removingPercentEncoding ?? body
            let expected = Data(SetupPlanner.revertScript().utf8).base64EncodedString()
            try check(decoded.contains(expected), "the revert script is sent, base64-encoded")
            try check(
                SetupPlanner.revertScript().contains("rm -f /usr/local/bin/e64local-action-run"),
                "the revert removes the runner"
            )
        },
    ]
}

// MARK: - Device probe

func proberChecks() -> [CheckCase] {
    let loginPage = """
    <html><head><title>Login Hemro E64 WS</title></head><body>
    <div class="label">MODEL</div><div class="value">E64 WS</div>
    <div class="label">S/N</div><div class="value">12345678</div>
    <div class="label">FW VERSION</div><div class="value">V01.16 build #24 (development)</div>
    <select><option value="Owner">Owner</option><option value="Developer">Developer</option></select>
    </body></html>
    """

    return [
        CheckCase("probe: the login page yields model, firmware and dev mode") {
            let fingerprint = try checkNotNil(Prober.parseLoginPage(loginPage), "fingerprint")
            try checkEqual(fingerprint.model, "E64 WS")
            try checkEqual(fingerprint.firmware, "V01.16 build #24 (development)")
            try checkEqual(fingerprint.devMode, true)
            try checkEqual(fingerprint.title, "E64 WS")
        },
        CheckCase("probe: a non-grinder page yields no fingerprint") {
            try checkNil(Prober.parseLoginPage("<html><title>Router</title></html>"), "router page")
            try checkNil(Prober.parseLoginPage(""), "empty page")
        },
        CheckCase("probe: an installed module is recognised by errorCode 401") {
            let state = Prober.classify(
                loginStatus: 200,
                fingerprint: DeviceProbe.Fingerprint(model: "E64 WS", firmware: "V01.16", devMode: true, title: ""),
                capabilities: jsonResponse(#"{"success":false,"errorCode":401,"error":"owner token required"}"#, status: 400)
            )
            try checkEqual(state, .moduleInstalled)
        },
        CheckCase("probe: the vendor 'unknown REST command' answer means the module is missing") {
            let state = Prober.classify(
                loginStatus: 200,
                fingerprint: DeviceProbe.Fingerprint(model: "E64 WS", firmware: "V01.16", devMode: true, title: ""),
                capabilities: jsonResponse(
                    #"{"console":"Error, unknown REST command","success":false,"errorCode":0}"#,
                    status: 400
                )
            )
            try checkEqual(state, .moduleMissing)
        },
        CheckCase("probe: an unauthenticated dispatcher answer is not an installed module") {
            let state = Prober.classify(
                loginStatus: 200,
                fingerprint: DeviceProbe.Fingerprint(model: "E64 WS", firmware: "V01.16", devMode: true, title: ""),
                capabilities: jsonResponse(
                    #"{"console":"Access denied!","success":false,"errorCode":0}"#,
                    status: 400
                )
            )
            try checkEqual(state, .moduleMissing)
        },
        CheckCase("probe: the capabilities probe carries the vendor session cookie") {
            let page = """
            <html><head><title>Login Hemro E64 WS</title></head><body>
            <div>MODEL</div><div>E64 WS</div>
            <div>FW VERSION</div><div>V01.16 build #24 (development)</div>
            </body></html>
            """
            let stub = StubTransport(responses: [
                "login.php": jsonResponse(page, setCookie: ["PHPSESSID=probe123; path=/; HttpOnly"]),
                "capabilities": jsonResponse(
                    #"{"success":false,"errorCode":401,"error":"owner token required"}"#,
                    status: 400
                ),
            ])
            let result = try await Prober.probe(
                endpoint: try Endpoint(host: "192.168.1.100"),
                transport: stub
            )
            try checkEqual(result.probe.state, .moduleInstalled)
            try checkNotNil(result.session, "session")
            let requests = await stub.requests
            let probeRequest = try checkNotNil(requests.last, "capabilities request")
            try checkEqual(probeRequest.url.path, "/rest_api/capabilities")
            try checkEqual(probeRequest.headers["Cookie"], "PHPSESSID=probe123")
        },
        CheckCase("probe: a dev-gate refusal is not offered a setup") {
            let probe = DeviceProbe(
                state: Prober.classify(
                    loginStatus: 200,
                    fingerprint: DeviceProbe.Fingerprint(model: "E64 WS", firmware: "V01.16", devMode: false, title: ""),
                    capabilities: jsonResponse(#"{"error":"dev mode required","success":false,"errorCode":403}"#, status: 403)
                )
            )
            try checkEqual(probe.state, .notDevelopmentImage)
            try checkEqual(probe.canSetup, false)
        },
        CheckCase("probe: a non-grinder login page is refused") {
            let state = Prober.classify(loginStatus: 200, fingerprint: nil, capabilities: nil)
            if case .notAGrinder = state {} else { throw CheckFailure(message: "expected notAGrinder, got \(state)", file: #filePath, line: #line) }
        },
        CheckCase("probe: the module can be set up when it is missing") {
            let probe = DeviceProbe(state: .moduleMissing)
            try checkEqual(probe.canSetup, true)
        },
        CheckCase("probe: a TLS rejection asks for explicit opt-in, not a bypass") {
            let state = Prober.classify(.tlsRejected("self-signed certificate"))
            if case .tlsUntrusted = state {} else {
                throw CheckFailure(message: "expected tlsUntrusted, got \(state)", file: #filePath, line: #line)
            }
        },
    ]
}

// MARK: - Redaction

func redactionChecks() -> [CheckCase] {
    [
        CheckCase("ats: the app's Info.plist allows local networking and nothing more") {
            let plist = URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent() // GrinderCoreChecksKit
                .deletingLastPathComponent() // Sources
                .deletingLastPathComponent() // GrinderCore
                .deletingLastPathComponent() // apps/ios
                .deletingLastPathComponent() // apps
                .deletingLastPathComponent() // repository root
                .appendingPathComponent("apps/ios/GrinderApp/Info.plist")
            guard FileManager.default.fileExists(atPath: plist.path) else { return }
            let data = try Data(contentsOf: plist)
            let object = try PropertyListSerialization.propertyList(from: data, format: nil)
            let root = try checkNotNil(object as? [String: Any], "root dictionary")
            let aps = try checkNotNil(root["NSAppTransportSecurity"] as? [String: Any], "NSAppTransportSecurity")
            try checkEqual(aps["NSAllowsLocalNetworking"] as? Bool, true, "NSAllowsLocalNetworking")
            try checkNil(aps["NSAllowsArbitraryLoads"], "NSAllowsArbitraryLoads must be absent")
            try checkNil(aps["NSExceptionDomains"], "no per-domain exceptions")
            let description = try checkNotNil(
                root["NSLocalNetworkUsageDescription"] as? String,
                "NSLocalNetworkUsageDescription"
            )
            try check(!description.isEmpty, "the local network reason must not be empty")
        },
        CheckCase("redaction: secrets, serials, MACs and IPs are removed") {
            let text = "password: hunter2 SN:AB12CD34 mac 00:1a:2b:3c:4d:5e ip 192.168.1.50 ok"
            let redacted = LogRedaction.redact(text)
            try check(!redacted.contains("hunter2"), "password")
            try check(!redacted.contains("AB12CD34"), "serial")
            try check(!redacted.contains("00:1a:2b"), "MAC")
            try check(!redacted.contains("192.168.1.50"), "IP")
            try check(redacted.contains("ok"), "non-secret text survives")
        },
        CheckCase("redaction: a token value is recognised as secret-shaped") {
            let token = OwnerToken.generate()
            try check(LogRedaction.looksSecret("token=\(token.value)"), "token=… should be redacted")
            try check(!LogRedaction.looksSecret("hello"), "plain text is not secret")
        },
    ]
}
