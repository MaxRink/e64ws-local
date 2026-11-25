import SwiftUI
import GrinderCore

/// Screen 5 — About & Security.
///
/// States the owner-token model, the development-image requirement and the
/// no-cloud promise in plain words, and offers to remove the device.
struct AboutView: View {
    @EnvironmentObject private var model: AppModel
    let onReconfigure: () -> Void

    @State private var confirmingForget = false
    @State private var removeFromGrinder = false

    var body: some View {
        NavigationStack {
            List {
                Section("This app") {
                    InfoRow(label: "Version", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                    InfoRow(label: "Device", value: model.configuration?.host ?? "not configured")
                    InfoRow(label: "Owner token", value: model.hasOwnerToken ? "in Keychain" : "missing")
                    if let configuration = model.configuration {
                        InfoRow(
                            label: "TLS",
                            value: configuration.pinnedCertificateSHA256 == nil ? "system validation" : "pinned to this device"
                        )
                    }
                }

                Section("No cloud") {
                    bullet("No account is needed and none is created.")
                    bullet("No telemetry, analytics, crash reporting or advertising identifiers.")
                    bullet("No vendor cloud or third party ever receives your data.")
                    bullet("The app talks only to the grinder you entered, on your local network. A device that resolves to a public address is refused.")
                }

                Section("Owner token") {
                    Text("""
                    Every local API request needs two things: the grinder's own web session and an owner token installed on the device at /db/e64local/token.

                    The token is generated on this phone, stored only in the iOS Keychain (this device only, never synced), sent as the X-E64-Local-Token header, and never written to a log. Losing it means running setup again to rotate it.
                    """)
                    .font(.callout)
                }

                Section("Development image required") {
                    Text("""
                    The local API only answers when the grinder runs a development image (/etc/issue starts with "development"). On a production image it refuses every request, and installing it does not change that.

                    Setup uses the same root path as the e64root tool: the vendor login form. It writes only the API module, the action runner and the owner token. It never writes to the ESP, firmware, NVS, bootloader or eFuses, and it never uploads firmware.
                    """)
                    .font(.callout)
                }

                Section("Read-only") {
                    Text("""
                    This app only reads: capabilities, machine identity, the grind, service and alert logs, recipes, portafilters, settings, the redacted machine config, and allowlisted files.

                    It cannot start a grind, move the motor, calibrate, pair, change settings or mint a WebSocket control token.

                    Setup also installs the root-owned action runner at /usr/local/bin/e64local-action-run, but it writes no /db/e64local/actions.json policy. Without that policy the grinder disables every action route, so the runner stays inert and this app never sends an action.
                    """)
                    .font(.callout)
                }

                Section {
                    Button(role: .destructive) {
                        confirmingForget = true
                    } label: {
                        Label("Forget this grinder", systemImage: "trash")
                    }
                    Button {
                        onReconfigure()
                    } label: {
                        Label("Change device", systemImage: "arrow.triangle.2.circlepath")
                    }
                } footer: {
                    Text("Forgetting removes the device and the owner token from this phone. You can also remove the local API from the grinder itself.")
                }
            }
            .navigationTitle("About & Security")
            .confirmationDialog("Forget this grinder?", isPresented: $confirmingForget, titleVisibility: .visible) {
                Button("Forget on this phone only") {
                    Task { await model.forgetDevice(removeFromGrinder: false) }
                }
                Button("Also remove local API from the grinder", role: .destructive) {
                    Task { await model.forgetDevice(removeFromGrinder: true) }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The device and its owner token are deleted from this phone. Removing the local API from the grinder deletes the module and the token file there.")
            }
        }
    }

    private func bullet(_ text: String) -> some View {
        Label(text, systemImage: "checkmark.circle")
            .font(.callout)
    }
}
