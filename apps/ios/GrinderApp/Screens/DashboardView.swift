import SwiftUI
import GrinderCore

/// Screen 2 — Dashboard: capabilities, machine identity and the vendor session.
struct DashboardView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            List {
                if let error = model.lastError {
                    Section { ErrorBanner(message: error) }
                }

                Section("Machine") {
                    if let machine = model.machine {
                        InfoRow(label: "Model", value: machine.model)
                        InfoRow(label: "Variant", value: machine.variant)
                        InfoRow(label: "Firmware", value: machine.firmware.isEmpty ? "unknown" : machine.firmware)
                        InfoRow(label: "Serial", value: machine.serialPresent ? "present (hashed)" : "absent")
                        if let serial = machine.serialSha256 {
                            InfoRow(label: "Serial SHA-256", value: serial, monospaced: true)
                        }
                        InfoRow(label: "Development image", value: machine.devMode ? "yes" : "no")
                    } else if model.isLoading {
                        ProgressView()
                    } else {
                        Text("No machine information yet.")
                            .foregroundStyle(.secondary)
                    }
                }

                if let capabilities = model.capabilities {
                    Section("Local API") {
                        InfoRow(label: "Version", value: "v\(capabilities.apiVersion)")
                        InfoRow(label: "Routes", value: "\(capabilities.routes.count)")
                        InfoRow(label: "Control actions", value: capabilities.features.actions ? "enabled" : "disabled")
                        InfoRow(label: "Max rows per page", value: "\(capabilities.limits.maxRows)")
                    }
                    Section("Available data") {
                        ForEach(capabilities.routes.filter { LocalAPI.dataRoutes.contains($0) }.sorted(), id: \.self) { route in
                            Text(route).font(.system(.body, design: .monospaced))
                        }
                    }
                }

                Section("Session") {
                    if model.isSessionActive {
                        Label("Signed in", systemImage: "person.crop.circle.badge.checkmark")
                            .foregroundStyle(.green)
                    } else {
                        SecureField("Owner password", text: $model.ownerPassword)
                        Button("Sign in to grinder") {
                            Task { await model.signIn(password: model.ownerPassword) }
                        }
                        .disabled(model.ownerPassword.isEmpty || model.isWorking)
                    }
                }
            }
            .navigationTitle("Dashboard")
            .refreshable { await model.refreshDashboard() }
            .task { await model.refreshDashboard() }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        Task { await model.refreshDashboard() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isLoading)
                }
            }
        }
    }
}
