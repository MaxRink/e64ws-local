import SwiftUI
import GrinderCore

/// Screen 1 — Setup.
///
/// Device address, TLS trust opt-in, probe, then one-click setup that installs
/// the local API and the owner token as root.  The exact commands are shown and
/// explicitly confirmed before anything is sent.
struct SetupView: View {
    @EnvironmentObject private var model: AppModel
    let onFinished: () -> Void

    @State private var confirmingSetup = false
    @State private var acceptingCertificate = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("192.168.1.100", text: $model.host)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Owner password", text: $model.ownerPassword)
                    Button {
                        Task { await model.probeDevice() }
                    } label: {
                        Label("Probe device", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .disabled(model.host.isEmpty || model.isWorking)
                } header: {
                    Text("Grinder")
                } footer: {
                    Text("The app talks only to this device, only on your local network.")
                }

                if let probe = model.probe {
                    probeSection(probe)
                }

                if let certificate = model.pendingCertificate {
                    certificateSection(certificate)
                }

                if model.probe?.canSetup == true {
                    Section {
                        Button {
                            Task {
                                await model.prepareSetupPlan()
                                confirmingSetup = model.setupPlan != nil
                            }
                        } label: {
                            Label("Set up local access", systemImage: "square.and.arrow.down.on.square")
                        }
                        .disabled(model.isWorking)
                    } footer: {
                        Text("Installs the local API and a new owner token on this grinder, as root. You will see every command before it runs.")
                    }
                }

                if model.canCompleteSetup {
                    Section {
                        Button {
                            Task { await model.completeSetup() }
                        } label: {
                            Label("Finish setup: verify local access", systemImage: "checkmark.seal")
                        }
                        .disabled(model.isWorking)
                    } footer: {
                        Text("The local API is already installed. This signs in and verifies the handshake without reinstalling anything.")
                    }
                }

                if !model.setupLog.isEmpty {
                    Section("Progress") {
                        ForEach(Array(model.setupLog.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(.footnote, design: .monospaced))
                        }
                    }
                }

                if let error = model.lastError {
                    Section { ErrorBanner(message: error) }
                }

                Section("No cloud, ever") {
                    Text("No account, no telemetry, no analytics and no vendor cloud. Your phone talks to your grinder and nothing else.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Set up your grinder")
            .toolbar {
                if model.phase == .ready {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel", action: onFinished)
                    }
                }
            }
            .sheet(isPresented: $confirmingSetup) {
                if let plan = model.setupPlan {
                    SetupConfirmationView(plan: plan) {
                        confirmingSetup = false
                        Task {
                            await model.runSetup()
                            if model.phase == .ready { onFinished() }
                        }
                    }
                }
            }
            .confirmationDialog(
                "Trust this certificate?",
                isPresented: $acceptingCertificate,
                titleVisibility: .visible
            ) {
                Button("Trust this device only") {
                    Task { await model.trustPendingCertificate() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Only accept a certificate you expect from your own grinder. It is pinned to this device alone; any other certificate is rejected.")
            }
        }
    }

    @ViewBuilder
    private func probeSection(_ probe: DeviceProbe) -> some View {
        Section("Device") {
            switch probe.state {
            case .reachable, .moduleInstalled, .moduleMissing:
                if let fingerprint = probe.fingerprint {
                    InfoRow(label: "Model", value: fingerprint.model.isEmpty ? "unknown" : fingerprint.model)
                    InfoRow(label: "Firmware", value: fingerprint.firmware.isEmpty ? "unknown" : fingerprint.firmware)
                    InfoRow(label: "Development image", value: fingerprint.devMode ? "yes" : "no")
                }
            case .notDevelopmentImage:
                InfoRow(label: "Development image", value: "no")
            case .notAGrinder(let detail), .unreachable(let detail), .tlsUntrusted(let detail):
                ErrorBanner(message: detail)
            }
            InfoRow(label: "Local API", value: apiStateText(probe.state))
        }
    }

    private func apiStateText(_ state: DeviceProbe.State) -> String {
        switch state {
        case .moduleInstalled: return "installed"
        case .moduleMissing: return "not installed yet"
        case .notDevelopmentImage: return "refused (development image required)"
        default: return "unknown"
        }
    }

    private func certificateSection(_ certificate: CertificateInfo) -> some View {
        Section("Server certificate") {
            InfoRow(label: "Common name", value: certificate.commonName.isEmpty ? "unknown" : certificate.commonName)
            InfoRow(label: "SHA-256", value: certificate.groupedFingerprint, monospaced: true)
            Button {
                acceptingCertificate = true
            } label: {
                Label("Trust this certificate for this device", systemImage: "checkmark.shield")
            }
            Text("The certificate is self-signed. Trusting it pins this exact certificate; the app still refuses any other certificate rather than skipping validation.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

/// The explicit confirmation screen: every command, then one button.
struct SetupConfirmationView: View {
    let plan: SetupPlan
    let onConfirm: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var acknowledged = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("These exact commands will run on your grinder as root through the vendor login form.")
                        .font(.callout)
                    ForEach(Array(plan.chunks.enumerated()), id: \.offset) { _, chunk in
                        Text(chunk)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    }
                    Text(plan.displayScript)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(plan.notes, id: \.self) { note in
                            Label(note, systemImage: "info.circle")
                                .font(.footnote)
                        }
                    }
                    Toggle("I understand this installs software on my grinder", isOn: $acknowledged)
                }
                .padding()
            }
            .navigationTitle("Confirm setup")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Install") { onConfirm() }
                        .disabled(!acknowledged)
                }
            }
        }
    }
}
