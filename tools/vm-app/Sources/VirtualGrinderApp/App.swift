import AppKit
import Foundation
import SwiftUI

@main
struct VirtualGrinderApp: App {
    @StateObject private var model = GrinderModel()

    var body: some Scene {
        WindowGroup("Mahlkönig Virtual Grinder") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1080, minHeight: 760)
                .onAppear {
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                }
                .task { await model.runLoop() }
                .task {
                    if let path = ProcessInfo.processInfo.environment["VG_APP_AUTOSNAP"], !path.isEmpty {
                        try? await Task.sleep(nanoseconds: 6_000_000_000)
                        saveWindowSnapshot(path: path)
                    }
                }
        }
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

@MainActor
final class GrinderModel: ObservableObject {
    @Published var screen: NSImage?
    @Published var stateText = "{\n  \"status\": \"waiting for daemon\"\n}"
    @Published var logsText = ""
    @Published var statusLine = "connecting…"
    @Published var lastError: String?
    @Published var busy = false
    @Published var weightG: Double = 18.0
    @Published var baseWeightG: Double = 0.0
    @Published var weightRate: Double = 2.0
    @Published var liveWeight: Double = 0.0
    @Published var grinding = false
    @Published var machineName = "E64 WS"
    @Published var clicks = 3
    @Published var ssid = "vg-lab"
    @Published var wifiPassword = "secret123"
    @Published var espEventID = "302"
    @Published var espEventData = "08 01"
    @Published var keysym = "0xff0d"
    @Published var wssMessage = #"{"type":"RequestDriverState","msgId":1}"#
    @Published var lastCommand = ""
    @Published var lastInput = "none"

    private let base = URL(string: ProcessInfo.processInfo.environment["VG_CONTROL_URL"]
                           ?? "http://127.0.0.1:28765")!
    private var lastScreenPath: String?
    private var tick = 0

    func runLoop() async {
        while !Task.isCancelled {
            await refresh()
            try? await Task.sleep(nanoseconds: 1_200_000_000)
        }
    }

    func refresh() async {
        if busy { return }
        busy = true
        defer { busy = false }
        await fetchState()
        await fetchLogs()
        tick += 1
        if tick % 2 == 0 || screen == nil { await captureScreen() }
    }

    private func fetchState() async {
        do {
            let data = try await get("/api/state")
            if let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
               let pretty = try? JSONSerialization.data(withJSONObject: object,
                                                       options: [.prettyPrinted, .sortedKeys]),
               let text = String(data: pretty, encoding: .utf8) {
                stateText = text
                statusLine = "VM \(status(object, "vm")) · guest \(status(object, "guest")) · ESP \(status(object, "esp"))"
                if let grinder = object["grinder"] as? [String: Any] {
                    liveWeight = grinder["weight_g"] as? Double ?? 0
                    baseWeightG = grinder["base_weight_g"] as? Double ?? 0
                    weightRate = grinder["weight_rate_g_per_s"] as? Double ?? 0
                    grinding = grinder["grinding"] as? Bool ?? false
                }
                lastError = nil
            }
        } catch {
            statusLine = "daemon unreachable"
            lastError = error.localizedDescription
        }
    }

    private func status(_ object: [String: Any], _ key: String) -> String {
        guard let child = object[key] as? [String: Any] else { return "?" }
        if let ok = child["ok"] as? Bool { return ok ? "ok" : "down" }
        if let running = child["running"] as? Bool { return running ? "up" : "down" }
        if let connected = child["connected"] as? Bool { return connected ? "up" : "down" }
        return "?"
    }

    private func fetchLogs() async {
        do {
            let data = try await get("/api/logs")
            let json = try JSONSerialization.jsonObject(with: data)
            let lines: [String]
            if let array = json as? [String] {
                lines = array
            } else if let object = json as? [String: Any],
                      let array = object["lines"] as? [String] {
                lines = array
            } else {
                lines = ["logs: unexpected response"]
            }
            logsText = lines.isEmpty ? "(no serial lines yet)" : lines.joined(separator: "\n")
        } catch {
            logsText = "logs error: \(error.localizedDescription)"
        }
    }

    private func captureScreen() async {
        let path = "/tmp/vg-app-screen.png"
        let result = await command("screen", ["path": path])
        guard result["ok"] as? Bool == true,
              let actual = result["path"] as? String,
              let image = NSImage(contentsOfFile: actual) else { return }
        lastScreenPath = actual
        screen = rotateClockwise(image)
    }

    func click(x: Int, y: Int) {
        Task { _ = await command("vnc", ["action": "click", "x": x, "y": y]) }
    }

    func key(_ name: String) {
        Task { _ = await command("key", ["name": name]) }
    }

    func keyDown(_ name: String) {
        Task { _ = await command("key", ["name": name, "value": 1]) }
    }

    func keyUp(_ name: String) {
        Task { _ = await command("key", ["name": name, "value": 0]) }
    }

    func keyHold(_ name: String, ms: Int = 900) {
        Task { _ = await command("key", ["name": name, "hold_ms": ms]) }
    }

    func keyDouble(_ name: String) {
        Task {
            _ = await command("key", ["name": name, "hold_ms": 60])
            try? await Task.sleep(nanoseconds: 80_000_000)
            _ = await command("key", ["name": name, "hold_ms": 60])
        }
    }

    func wssAction(_ action: String, data: [String: Any] = [:]) {
        Task { _ = await sendAction(action, data: data) }
    }

    @discardableResult
    private func sendAction(_ action: String, data: [String: Any] = [:]) async -> [String: Any] {
        var payload: [String: Any] = ["actionType": action]
        for (key, value) in data { payload[key] = value }
        let message: [String: Any] = [
            "type": "GrinderAction",
            "msgId": Int(Date().timeIntervalSince1970 * 1000) % 1_000_000,
            "data": payload,
        ]
        return await command("wss", ["message": message])
    }

    func dismissAlerts() {
        Task {
            // First-boot vendor alerts: calibration missing, then security data.
            // Two rounds are needed because each alert consumes one gesture.
            for _ in 0..<3 {
                for action in ["RcBottomLeftClick", "RcTopLeftLong", "RcRotaryClick"] {
                    _ = await sendAction(action)
                    try? await Task.sleep(nanoseconds: 900_000_000)
                }
            }
        }
    }

    private func note(_ value: String) {
        lastInput = value
    }

    func panelTap(_ key: String) {
        note("\(key) tap")
        switch key {
        case "top": wssAction("RcTopLeftClick")
        case "bottom": wssAction("RcBottomLeftClick")
        case "rotary": wssAction("RcRotaryClick")
        default: self.key(key)
        }
    }

    func panelDown(_ key: String) {
        note("\(key) press")
        switch key {
        case "top": wssAction("RcTopLeftPress")
        default: keyDown(key)
        }
    }

    func panelUp(_ key: String) {
        note("\(key) release")
        switch key {
        case "top": wssAction("RcTopLeftRelease")
        default: keyUp(key)
        }
    }

    func panelLong(_ key: String) {
        note("\(key) long")
        switch key {
        case "top": wssAction("RcTopLeftLong")
        case "rotary": wssAction("RcRotaryLong")
        default: keyHold(key)
        }
    }

    func panelDouble(_ key: String) {
        note("\(key) double")
        switch key {
        case "rotary": wssAction("RcRotaryDouble")
        default: keyDouble(key)
        }
    }

    func rotaryTicks(_ ticks: Int) {
        guard ticks != 0 else { return }
        note("rotary \(ticks > 0 ? "+" : "") \(ticks) tick\(abs(ticks) == 1 ? "" : "s")")
        Task { _ = await command("rotate", ["clicks": ticks]) }
    }

    func rotate(_ delta: Int) {
        Task { _ = await command("rotate", ["clicks": delta]) }
    }

    func setWeight(_ grams: Double) {
        weightG = grams
        Task { _ = await command("weight", ["grams": grams]) }
    }

    func setBaseWeight(_ grams: Double) {
        baseWeightG = grams
        Task { _ = await command("weight.base", ["grams": grams]) }
    }

    func setWeightRate(_ rate: Double) {
        weightRate = rate
        Task { _ = await command("weight.rate", ["grams_per_s": rate]) }
    }

    func weightAuto(_ start: Bool) {
        Task { _ = await command(start ? "weight.start" : "weight.stop", [:]) }
    }

    func wifi(_ action: String) {
        Task {
            switch action {
            case "scan": _ = await command("wifi.scan", [:])
            case "join": _ = await command("wifi.join", ["ssid": ssid, "password": wifiPassword])
            default: _ = await command("wifi.off", [:])
            }
        }
    }

    func espEvent() {
        Task {
            _ = await command("esp.event", ["id": Int(espEventID) ?? 302,
                                            "data_hex": espEventData])
        }
    }

    func power(_ action: String) {
        Task { _ = await command("power", ["action": action]) }
    }

    func grind(_ action: String) {
        Task {
            if action == "start" {
                _ = await command("grind.start", ["mode": "manual"])
            } else {
                _ = await command("grind.stop", [:])
            }
        }
    }

    func sendVNCKey() {
        let value = keysym.lowercased().hasPrefix("0x")
            ? String(keysym.dropFirst(2)) : keysym
        let code = Int(value, radix: 16) ?? 0xff0d
        Task { _ = await command("vnc", ["action": "key", "keysym": code]) }
    }

    func sendWSS() {
        Task { _ = await command("wss", ["json_message": wssMessage]) }
    }

    func snapshot() {
        Task {
            let result = await command("screen", ["path": "/tmp/vg-app-snapshot-\(Int(Date().timeIntervalSince1970)).png"])
            lastCommand = (result["path"] as? String) ?? "snapshot failed"
        }
    }

    @discardableResult
    private func command(_ cmd: String, _ args: [String: Any]) async -> [String: Any] {
        do {
            var request = URLRequest(url: base.appendingPathComponent("/api/cmd"))
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["cmd": cmd, "args": args])
            let (data, _) = try await URLSession.shared.data(for: request)
            let result = (try JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
            lastCommand = "\(cmd) → \(result["ok"] as? Bool == true ? "ok" : "error")"
            if result["ok"] as? Bool != true { lastError = result["error"] as? String }
            return result
        } catch {
            lastError = error.localizedDescription
            return ["ok": false, "error": error.localizedDescription]
        }
    }

    private func get(_ path: String) async throws -> Data {
        guard let url = URL(string: path, relativeTo: base) else {
            throw URLError(.badURL)
        }
        let (data, _) = try await URLSession.shared.data(from: url)
        return data
    }
}


@MainActor
func rotateClockwise(_ image: NSImage) -> NSImage {
    let src = image.size
    let out = NSImage(size: NSSize(width: src.height, height: src.width))
    out.lockFocus()
    if let ctx = NSGraphicsContext.current?.cgContext {
        ctx.translateBy(x: src.height / 2, y: src.width / 2)
        ctx.rotate(by: .pi / 2)
        image.draw(in: NSRect(x: -src.width / 2, y: -src.height / 2,
                              width: src.width, height: src.height))
    }
    out.unlockFocus()
    return out
}
