import AppKit
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: GrinderModel
    @StateObject private var tabs = TabModel()

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HSplitView {
                displayPane
                    .frame(minWidth: 360, idealWidth: 400, maxWidth: 520)
                inspector
                    .frame(minWidth: 560)
            }
            Divider()
            footer
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear {
            if let raw = ProcessInfo.processInfo.environment["VG_APP_TAB"],
               let value = Int(raw) { tabs.tab = value }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "cup.and.saucer.fill")
                .font(.title2)
            VStack(alignment: .leading, spacing: 2) {
                Text("Mahlkönig Virtual Grinder")
                    .font(.headline)
                Text(model.statusLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await model.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .keyboardShortcut("r")
            Button {
                model.dismissAlerts()
            } label: {
                Label("Dismiss alerts", systemImage: "exclamationmark.triangle")
            }
            Button {
                model.snapshot()
            } label: {
                Label("Snapshot", systemImage: "camera")
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var displayPane: some View {
        VStack(spacing: 8) {
            HStack {
                Text("HMI display")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("480 × 320 · rotated 90°")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                VStack(spacing: 18) {
                    PanelButton(symbol: "chevron.up", label: "TOP") {
                        model.panelTap("top")
                    } onLong: {
                        model.panelLong("top")
                    }
                    PanelButton(symbol: "chevron.down", label: "BOTTOM") {
                        model.panelTap("bottom")
                    } onLong: {
                        model.keyHold("bottom")
                    }
                }
                DisplayView()
                    .background(Color.black)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
                VStack(spacing: 8) {
                    RotaryKnob(onTicks: { model.rotaryTicks($0) },
                               onTap: { model.panelTap("rotary") },
                               onLong: { model.panelLong("rotary") },
                               onDouble: { model.panelDouble("rotary") })
                        .frame(width: 94, height: 94)
                    Text("ROTARY").font(.caption2).foregroundStyle(.secondary)
                    HStack(spacing: 3) {
                        Button("−10") { model.rotaryTicks(-10) }
                            .help("Ten ticks counter-clockwise")
                        Button("−1") { model.rotaryTicks(-1) }
                            .help("One tick counter-clockwise")
                        Button("+1") { model.rotaryTicks(1) }
                            .help("One tick clockwise")
                        Button("+10") { model.rotaryTicks(10) }
                            .help("Ten ticks clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .fixedSize()
                    HStack(spacing: 3) {
                        Button("Click") { model.panelTap("rotary") }
                        Button("Long") { model.panelLong("rotary") }
                        Button("Double") { model.panelDouble("rotary") }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .fixedSize()
                    Text(model.lastInput)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(maxWidth: 150)
                }
            }
            Text("Click the buttons, drag the rotary knob, or use the full event matrix below. Pointer clicks are sent to the HMI but the vendor QML ignores them; the panel inputs are the working path.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
    }

    private var inspector: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tabs.tab) {
                Text("Controls").tag(0)
                Text("Machine").tag(1)
                Text("Internal state").tag(2)
                Text("Logs").tag(3)
            }
            .pickerStyle(.segmented)
            .padding(10)
            Divider()
            Group {
                switch tabs.tab {
                case 0: ControlsView()
                case 1: MachineView()
                case 2: StateView()
                default: LogsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var footer: some View {
        HStack {
            Text(model.lastCommand.isEmpty ? "ready" : model.lastCommand)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Spacer()
            if let error = model.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}

final class TabModel: ObservableObject {
    @Published var tab = 0
}

struct DisplayView: View {
    @EnvironmentObject private var model: GrinderModel

    var body: some View {
        GeometryReader { geo in
            let aspect: CGFloat = 480.0 / 320.0
            let fitted: CGSize = {
                if geo.size.width / max(geo.size.height, 1) > aspect {
                    return CGSize(width: geo.size.height * aspect, height: geo.size.height)
                }
                return CGSize(width: geo.size.width, height: geo.size.width / aspect)
            }()
            let origin = CGPoint(x: (geo.size.width - fitted.width) / 2,
                                 y: (geo.size.height - fitted.height) / 2)
            ZStack {
                Color.black
                if let image = model.screen {
                    Image(nsImage: image)
                        .resizable()
                        .interpolation(.none)
                        .frame(width: fitted.width, height: fitted.height)
                        .position(x: origin.x + fitted.width / 2,
                                  y: origin.y + fitted.height / 2)
                } else {
                    VStack(spacing: 8) {
                        ProgressView()
                        Text("waiting for the HMI frame")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .contentShape(Rectangle())
            .gesture(
                SpatialTapGesture()
                    .onEnded { value in
                        guard fitted.width > 0, fitted.height > 0 else { return }
                        let local = value.location
                        guard local.x >= origin.x, local.x <= origin.x + fitted.width,
                              local.y >= origin.y, local.y <= origin.y + fitted.height else { return }
                        let dx = (local.x - origin.x) / fitted.width
                        let dy = (local.y - origin.y) / fitted.height
                        // The displayed image is the 320x480 framebuffer rotated
                        // 90 degrees clockwise: dest x = 479 - v, dest y = u.
                        let u = Int(dy * 320)
                        let v = 479 - Int(dx * 480)
                        model.click(x: max(0, min(319, u)), y: max(0, min(479, v)))
                    }
            )
        }
    }
}

struct ControlsView: View {
    @EnvironmentObject private var model: GrinderModel

    private let keys = ["top", "bottom", "rotary", "ddd", "hopper", "agsa"]
    private let keyLabels = ["top": "Top ▲", "bottom": "Bottom ▼", "rotary": "Rotary ◉",
                             "ddd": "DDD", "hopper": "Hopper", "agsa": "AGSA"]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                group("Front panel — every input level") {
                    ForEach(keys, id: \.self) { key in
                        HStack(spacing: 6) {
                            Text(keyLabels[key] ?? key)
                                .font(.caption)
                                .frame(width: 74, alignment: .leading)
                            Button("Tap") { model.panelTap(key) }
                            Button("Press") { model.panelDown(key) }
                            Button("Release") { model.panelUp(key) }
                            Button("Long") { model.panelLong(key) }
                            Button("Double") { model.panelDouble(key) }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    Text("Tap = normal click · Press/Release = held level (use for chords and release events) · Long = 900 ms hold · Double = two short presses. Top, Bottom and Rotary use the vendor WSS actions; DDD/Hopper/AGSA use the GPIO key line.")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                group("Rotary — ticks, click, long, double") {
                    HStack(spacing: 14) {
                        RotaryKnob(onTicks: { model.rotaryTicks($0) },
                                   onTap: { model.panelTap("rotary") },
                                   onLong: { model.panelLong("rotary") },
                                   onDouble: { model.panelDouble("rotary") })
                            .frame(width: 96, height: 96)
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                TextField("Ticks", value: $model.clicks, format: .number)
                                    .frame(width: 64)
                                Button("−") { model.rotaryTicks(-abs(model.clicks)) }
                                Button("+") { model.rotaryTicks(abs(model.clicks)) }
                            }
                            HStack {
                                Button("Click") { model.panelTap("rotary") }
                                Button("Long") { model.panelLong("rotary") }
                                Button("Double") { model.panelDouble("rotary") }
                            }
                            HStack {
                                Button("Press") { model.panelDown("rotary") }
                                Button("Release") { model.panelUp("rotary") }
                            }
                        }
                    }
                    Text("Drag the knob clockwise/counter-clockwise; each 18 pt is one REL_DIAL tick. Click/Long/Double map to RcRotaryClick/RcRotaryLong/RcRotaryDouble.")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                group("Load cell / scale simulation") {
                    HStack {
                        Text("Live").foregroundStyle(.secondary)
                        Text(String(format: "%.2f g", model.liveWeight))
                            .font(.system(.body, design: .monospaced))
                        if model.grinding { Text("GRINDING").font(.caption.bold()).foregroundStyle(.orange) }
                        Spacer()
                    }
                    HStack {
                        Text("Basket tare").font(.caption)
                        TextField("g", value: $model.baseWeightG, format: .number.precision(.fractionLength(1)))
                            .frame(width: 70)
                            .onSubmit { model.setBaseWeight(model.baseWeightG) }
                        Button("Set base") { model.setBaseWeight(model.baseWeightG) }
                        Spacer()
                    }
                    HStack {
                        Text("Grind rate").font(.caption)
                        TextField("g/s", value: $model.weightRate, format: .number.precision(.fractionLength(1)))
                            .frame(width: 70)
                            .onSubmit { model.setWeightRate(model.weightRate) }
                        Text("g/s").foregroundStyle(.secondary)
                        Button("Apply") { model.setWeightRate(model.weightRate) }
                        Spacer()
                    }
                    HStack {
                        Button("Start weight ramp") { model.weightAuto(true) }
                        Button("Stop ramp") { model.weightAuto(false) }
                        Button("Tare now") { model.setWeight(0); model.setBaseWeight(0) }
                        Spacer()
                    }
                    Text("The grinder sees the base weight at idle and a rising weight while grinding, emulating basket detection and a real dose.")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                group("Wi-Fi (virtual ESP32)") {
                    HStack {
                        TextField("SSID", text: $model.ssid)
                        SecureField("Password", text: $model.wifiPassword)
                    }
                    HStack {
                        Button("Scan") { model.wifi("scan") }
                        Button("Join") { model.wifi("join") }
                        Button("Off") { model.wifi("off") }
                        Spacer()
                    }
                }

                group("ESP event") {
                    HStack {
                        TextField("ID", text: $model.espEventID).frame(width: 70)
                        TextField("protobuf body (hex)", text: $model.espEventData)
                        Button("Send") { model.espEvent() }
                    }
                    Text("Asynchronous event on /dev/esps0: 301–304 are the vendor event IDs; the body is protobuf-C hex. 302 is a status event. The reply/effect appears in Internal state → esp.")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                group("Grind") {
                    HStack {
                        Button("Start manual") { model.grind("start") }
                        Button("Stop") { model.grind("stop") }
                        Spacer()
                    }
                }

                group("Power") {
                    HStack {
                        Button("Reset") { model.power("reset") }
                        Button("Reboot") { model.power("reboot") }
                        Button("Shutdown") { model.power("shutdown") }
                        Button("Off") { model.power("off") }
                        Spacer()
                    }
                }

                group("WSS command") {
                    TextField("JSON message", text: $model.wssMessage, axis: .vertical)
                        .lineLimit(2...4)
                        .font(.system(.caption, design: .monospaced))
                    HStack {
                        Button("Send WSS") { model.sendWSS() }
                        Spacer()
                    }
                    Text("Plain JSON over wss://127.0.0.1:29997. A read-only query uses type + msgId; actions use {\"type\":\"GrinderAction\",\"data\":{\"actionType\":\"...\"}}. Invalid or gated messages close the socket without a reply.")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                group("VNC key") {
                    HStack {
                        TextField("keysym (hex)", text: $model.keysym)
                            .frame(width: 120)
                        Button("Send") { model.sendVNCKey() }
                        Spacer()
                    }
                }
            }
            .padding(12)
        }
    }

    private func group<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            content()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct StateView: View {
    @EnvironmentObject private var model: GrinderModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Complete daemon state (VM, guest agent, ESP, scale, grinder, control).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)
            TextEditor(text: .constant(model.stateText))
                .font(.system(.caption, design: .monospaced))
                .padding(6)
        }
    }
}

struct LogsView: View {
    @EnvironmentObject private var model: GrinderModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Serial console (last 120 lines, refreshed with the state).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)
            TextEditor(text: .constant(model.logsText))
                .font(.system(.caption2, design: .monospaced))
                .padding(6)
        }
    }
}


@MainActor
func saveWindowSnapshot(path: String) {
    NSLog("snapshot: windows=%d", NSApp.windows.count)
    guard let window = NSApp.windows.first(where: { $0.isVisible }) ?? NSApp.windows.first,
          let view = window.contentView,
          view.bounds.width > 1, view.bounds.height > 1 else {
        NSLog("snapshot: no usable window"); return
    }
    NSLog("snapshot: view=%@", NSStringFromRect(view.bounds))
    if let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
        view.cacheDisplay(in: view.bounds, to: rep)
        if let data = rep.representation(using: .png, properties: [:]) {
            do { try data.write(to: URL(fileURLWithPath: path)); NSLog("snapshot: wrote %@", path) }
            catch { NSLog("snapshot: png write failed %@", error.localizedDescription) }
            return
        }
    }
    let pdf = view.dataWithPDF(inside: view.bounds)
    do { try pdf.write(to: URL(fileURLWithPath: path + ".pdf")); NSLog("snapshot: wrote %@.pdf", path) }
    catch { NSLog("snapshot: pdf write failed %@", error.localizedDescription) }
}


struct PanelButton: View {
    let symbol: String
    let label: String
    let action: () -> Void
    let onLong: () -> Void

    var body: some View {
        VStack(spacing: 4) {
            Button(action: action) {
                Image(systemName: symbol)
                    .font(.system(size: 18, weight: .bold))
                    .frame(width: 44, height: 44)
                    .background(Circle().fill(Color(red: 0.22, green: 0.23, blue: 0.25)))
                    .overlay(Circle().stroke(.white.opacity(0.25), lineWidth: 1))
                    .foregroundStyle(.white)
            }
            .buttonStyle(.plain)
            .onLongPressGesture(minimumDuration: 0.9) { onLong() }
            Text(label).font(.system(size: 8, weight: .semibold)).foregroundStyle(.secondary)
        }
    }
}

struct RotaryKnob: View {
    let onTicks: (Int) -> Void
    let onTap: () -> Void
    let onLong: () -> Void
    let onDouble: () -> Void
    @StateObject private var state = KnobState()

    var body: some View {
        ZStack {
            Circle()
                .fill(Color(nsColor: .controlBackgroundColor))
                .overlay(Circle().stroke(.white.opacity(0.25), lineWidth: 2))
            ForEach(0..<12, id: \.self) { i in
                Capsule()
                    .fill(i % 3 == 0 ? Color.accentColor : Color.secondary.opacity(0.6))
                    .frame(width: 2, height: i % 3 == 0 ? 10 : 6)
                    .offset(y: -36)
                    .rotationEffect(.degrees(Double(i) * 30))
            }
            Capsule()
                .fill(Color.accentColor)
                .frame(width: 3, height: 30)
                .offset(y: -14)
                .rotationEffect(.degrees(state.angle))
            Circle()
                .fill(Color(nsColor: .windowBackgroundColor))
                .frame(width: 22, height: 22)
        }
        .contentShape(Circle())
        .help("Drag clockwise/counter-clockwise for ticks; click, long-press or double-click for the other rotary levels")
        .onTapGesture(count: 2) { onDouble() }
        .onTapGesture { onTap() }
        .onLongPressGesture(minimumDuration: 0.9) { onLong() }
        .gesture(
            DragGesture(minimumDistance: 1)
                .onChanged { value in
                    let total = value.translation.width
                    let delta = total - state.lastTranslation
                    state.lastTranslation = total
                    state.tickAccum += delta
                    state.angle = total * 0.65
                    let ticks = Int(state.tickAccum / 12)
                    if ticks != 0 {
                        state.tickAccum -= CGFloat(ticks) * 12
                        onTicks(ticks)
                    }
                }
                .onEnded { _ in
                    state.angle = 0
                    state.lastTranslation = 0
                    state.tickAccum = 0
                }
        )
    }
}

final class KnobState: ObservableObject {
    @Published var angle: Double = 0
    var lastTranslation: CGFloat = 0
    var tickAccum: CGFloat = 0
}
