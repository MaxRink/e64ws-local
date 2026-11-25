import SwiftUI
import GrinderCore

@main
struct GrinderApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                // Dark-friendly but respects the system; no custom theming.
                .tint(.accentColor)
        }
    }
}

/// Switches between setup and the main tabs.
struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingSetup = false

    var body: some View {
        Group {
            if model.phase == .ready && !showingSetup {
                MainTabView(onReconfigure: { showingSetup = true })
            } else {
                SetupView(onFinished: { showingSetup = false })
            }
        }
    }
}

struct MainTabView: View {
    @EnvironmentObject private var model: AppModel
    let onReconfigure: () -> Void

    var body: some View {
        TabView {
            DashboardView()
                .tabItem { Label("Dashboard", systemImage: "gauge.with.dots.needle.bottom.50percent") }
            LogsView()
                .tabItem { Label("Logs", systemImage: "list.bullet.rectangle") }
            DataView()
                .tabItem { Label("Data", systemImage: "tray.full") }
            AboutView(onReconfigure: onReconfigure)
                .tabItem { Label("About & Security", systemImage: "lock.shield") }
        }
    }
}

/// A labelled value row used across the screens.
struct InfoRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .font(monospaced ? .system(.body, design: .monospaced) : .body)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}

/// An inline error banner that never includes request details.
struct ErrorBanner: View {
    let message: String

    var body: some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
    }
}
