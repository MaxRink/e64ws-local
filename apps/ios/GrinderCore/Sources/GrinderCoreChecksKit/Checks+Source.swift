import Foundation
import GrinderCore

/// The repository root, derived from this file's location:
/// `<root>/apps/ios/GrinderCore/Sources/GrinderCoreChecksKit/Checks+Source.swift`.
func repositoryRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // GrinderCoreChecksKit
        .deletingLastPathComponent() // Sources
        .deletingLastPathComponent() // GrinderCore
        .deletingLastPathComponent() // apps/ios
        .deletingLastPathComponent() // apps
        .deletingLastPathComponent() // repository root
}

/// Read a file that must exist.  A missing file is a failed check, never a
/// silent pass: a source check that cannot read its subject proves nothing.
func sourceText(at url: URL) throws -> String {
    var lastError: Error?
    for _ in 0..<5 {
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            lastError = error
            Thread.sleep(forTimeInterval: 0.05)
        }
    }
    throw CheckFailure(
        message: "cannot read \(url.path): \(lastError?.localizedDescription ?? "unknown error")",
        file: #filePath,
        line: #line
    )
}

/// The first logging call in `source`, or nil.  `print(` must start a token, so
/// `Fingerprint(` and `debugPrint(` are not logging calls.
func loggingCall(in source: String) -> String? {
    for pattern in ["print(", "debugPrint(", "NSLog(", "os_log("] {
        var search = source.startIndex..<source.endIndex
        while let found = source.range(of: pattern, range: search) {
            if found.lowerBound == source.startIndex
                || !source[source.index(before: found.lowerBound)].isLetter {
                return pattern
            }
            search = found.upperBound..<source.endIndex
        }
    }
    return nil
}

/// Checks over the app's own source and resources, so the security promises in
/// the README are enforced rather than merely written down.
func sourceChecks() -> [CheckCase] {
    let iosRoot = repositoryRoot().appendingPathComponent("apps/ios")

    /// The app's own Swift sources (views and model).
    let appSources = [
        "GrinderApp/AppModel.swift",
        "GrinderApp/GrinderApp.swift",
        "GrinderApp/Screens/SetupView.swift",
        "GrinderApp/Screens/DashboardView.swift",
        "GrinderApp/Screens/LogsView.swift",
        "GrinderApp/Screens/DataView.swift",
        "GrinderApp/Screens/AboutView.swift",
    ]

    /// Every source of the core library, so a new file cannot escape the rules.
    @Sendable
    func coreSources() throws -> [(name: String, text: String)] {
        let directory = iosRoot.appendingPathComponent("GrinderCore/Sources/GrinderCore")
        guard let walker = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil) else {
            throw CheckFailure(message: "cannot enumerate \(directory.path)", file: #filePath, line: #line)
        }
        var files: [(name: String, text: String)] = []
        for case let url as URL in walker where url.pathExtension == "swift" {
            files.append((url.lastPathComponent, try sourceText(at: url)))
        }
        try check(!files.isEmpty, "no GrinderCore sources found")
        return files.sorted { $0.name < $1.name }
    }

    return [
        CheckCase("source: the app never calls the ws_token route") {
            let app = try sourceText(at: iosRoot.appendingPathComponent("GrinderCore/Sources/GrinderCore/Client/LocalAPI.swift"))
            try check(!app.contains("\"ws_token\""), "LocalAPI must not reference ws_token as a route")
            try check(!app.contains("mintWsToken"), "no WSS token minting")
        },
        CheckCase("source: there is no println/print/NSLog/os_log in app or core") {
            var subjects: [(name: String, text: String)] = []
            for file in appSources {
                subjects.append((file, try sourceText(at: iosRoot.appendingPathComponent(file))))
            }
            subjects.append(contentsOf: try coreSources())
            for subject in subjects {
                if let pattern = loggingCall(in: subject.text) {
                    throw CheckFailure(
                        message: "\(subject.name) contains \(pattern)",
                        file: #filePath,
                        line: #line
                    )
                }
            }
        },
        CheckCase("source: ATS never disables validation") {
            let plist = try sourceText(at: iosRoot.appendingPathComponent("GrinderApp/Info.plist"))
            try check(!plist.contains("NSAllowsArbitraryLoadsInWebContent"), "no web-content exception")
            try check(!plist.contains("NSAllowsArbitraryLoads<"), "no arbitrary-loads exception")
            try check(!plist.contains("kCFNetwork"), "no low-level TLS bypass")
            try check(plist.contains("NSAllowsLocalNetworking"), "local networking opt-in")
        },
        CheckCase("source: the bundled resources exist for the Xcode target too") {
            for name in ["rest_api_dev.php", "e64local_action_run.php"] {
                let bundled = try sourceText(at: iosRoot.appendingPathComponent("GrinderApp/Resources/\(name)"))
                let core = try sourceText(at: iosRoot.appendingPathComponent("GrinderCore/Sources/GrinderCore/Resources/\(name)"))
                try checkEqual(bundled, core, "\(name): the app resource and the package resource agree")
            }
        },
        CheckCase("source: core imports only Foundation, CryptoKit and Security") {
            let allowed: Set<String> = ["Foundation", "CryptoKit", "Security"]
            for source in try coreSources() {
                for line in source.text.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    guard trimmed.hasPrefix("import ") else { continue }
                    let module = String(trimmed.dropFirst("import ".count))
                    try check(allowed.contains(module), "\(source.name) imports \(module)")
                }
            }
        },
        CheckCase("source: the owner token is this-device-only, unsynced and from the CSPRNG") {
            let source = try sourceText(at: iosRoot.appendingPathComponent("GrinderCore/Sources/GrinderCore/Auth/TokenStore.swift"))
            try check(source.contains("SecRandomCopyBytes"), "SecRandomCopyBytes")
            try check(source.contains("kSecAttrAccessibleWhenUnlockedThisDeviceOnly"), "accessibility class")
            try check(source.contains("kSecAttrSynchronizable as String] = false"), "synchronizable is off")
            try check(!source.contains("UserDefaults"), "the token never goes to UserDefaults")
            try check(!source.contains("print("), "the token is never printed")
        },
        CheckCase("source: no secrets or absolute developer paths in the app sources") {
            for file in appSources {
                let source = try sourceText(at: iosRoot.appendingPathComponent(file))
                try check(!source.contains("/Users/"), "\(file) has an absolute home path")
                try check(!source.contains("tokenHex: \""), "\(file) has a hard-coded token")
            }
        },
    ]
}
