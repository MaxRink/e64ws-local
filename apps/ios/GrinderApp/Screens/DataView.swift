import SwiftUI
import GrinderCore

/// Screen 4 — Data: recipes, portafilters, settings, config and one allowlisted
/// file.  Read-only throughout.
struct DataView: View {
    var body: some View {
        NavigationStack {
            List {
                Section("Grinder data") {
                    NavigationLink("Recipes") { TableScreen(title: "Recipes", source: .recipes) }
                    NavigationLink("Portafilters") { TableScreen(title: "Portafilters", source: .portafilters) }
                }
                Section("Configuration") {
                    NavigationLink("Settings") { SettingsScreen() }
                    NavigationLink("Machine config") { ConfigScreen() }
                }
                Section("Files") {
                    NavigationLink("Allowlisted file") { FileScreen() }
                }
            }
            .navigationTitle("Data")
        }
    }
}

/// A generic `RowTable` screen (recipes, portafilters).
struct TableScreen: View {
    /// Which read-only route to load.
    enum Source {
        case recipes
        case portafilters
    }

    @EnvironmentObject private var model: AppModel
    let title: String
    let source: Source

    @State private var rows: [Row] = []
    @State private var error: String?
    @State private var isLoading = false

    var body: some View {
        List {
            if let error { Section { ErrorBanner(message: error) } }
            ForEach(rows) { row in
                NavigationLink {
                    RowDetailView(title: title, row: row)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.titleText).font(.headline)
                        Text(row.subtitleText).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
            }
            if rows.isEmpty && !isLoading && error == nil {
                Text("Nothing returned.").foregroundStyle(.secondary)
            }
        }
        .overlay { if isLoading && rows.isEmpty { ProgressView() } }
        .navigationTitle(title)
        .refreshable { await refresh() }
        .task { await refresh() }
    }

    private func refresh() async {
        isLoading = true
        defer { isLoading = false }
        do {
            switch source {
            case .recipes: rows = try await model.loadRecipes().rows
            case .portafilters: rows = try await model.loadPortafilters().rows
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

extension Row {
    var titleText: String {
        if let index = self["recipe_index"] { return "Recipe \(index)" }
        if let id = self["portafilter_id"] { return "Portafilter \(id)" }
        return orderedColumns.first.flatMap { self[$0] } ?? "Row"
    }

    var subtitleText: String {
        if let type = self["recipe_type"], let mode = self["recipe_mode"] {
            return "\(type) · \(mode)"
        }
        if let weight = self["weight"], let tolerance = self["weight_tolerance"] {
            return "\(weight) g ± \(tolerance) g"
        }
        return self["recipe_mode"] ?? ""
    }
}

/// `settings`: flat key/value with the omitted keys listed.
struct SettingsScreen: View {
    @EnvironmentObject private var model: AppModel
    @State private var export: SettingsExport?
    @State private var error: String?
    @State private var isLoading = false

    var body: some View {
        List {
            if let error { Section { ErrorBanner(message: error) } }
            if let export {
                Section("Values (\(export.count))") {
                    ForEach(export.sortedKeys, id: \.self) { key in
                        InfoRow(label: key, value: export.settings[key] ?? "", monospaced: true)
                    }
                }
                if !export.redacted.isEmpty {
                    Section("Redacted by the grinder") {
                        ForEach(export.redacted, id: \.self) { key in
                            Text(key).font(.system(.footnote, design: .monospaced)).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .overlay { if isLoading && export == nil { ProgressView() } }
        .navigationTitle("Settings")
        .refreshable { await refresh() }
        .task { await refresh() }
    }

    private func refresh() async {
        isLoading = true
        defer { isLoading = false }
        do {
            export = try await model.loadSettings()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// `config`: the machine config with sensitive values replaced by the device.
struct ConfigScreen: View {
    @EnvironmentObject private var model: AppModel
    @State private var export: ConfigExport?
    @State private var error: String?
    @State private var isLoading = false
    @State private var selected: (key: String, field: JSONField)?

    var body: some View {
        List {
            if let error { Section { ErrorBanner(message: error) } }
            if let export {
                Section("Values") {
                    ForEach(export.config.keys.sorted(), id: \.self) { key in
                        Button {
                            selected = (key, export.config[key] ?? .null)
                        } label: {
                            InfoRow(label: key, value: export.config[key]?.displayText ?? "")
                        }
                        .buttonStyle(.plain)
                    }
                }
                if !export.redacted.isEmpty {
                    Section("Redacted by the grinder") {
                        ForEach(export.redacted, id: \.self) { path in
                            Text(path).font(.system(.footnote, design: .monospaced)).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .overlay { if isLoading && export == nil { ProgressView() } }
        .navigationTitle("Machine config")
        .refreshable { await refresh() }
        .task { await refresh() }
        .sheet(item: Binding(
            get: { selected.map { Selection(key: $0.key, field: $0.field) } },
            set: { if $0 == nil { selected = nil } }
        )) { selection in
            NavigationStack {
                ScrollView {
                    Text(selection.field.prettyJSON)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .navigationTitle(selection.key)
            }
        }
    }

    struct Selection: Identifiable {
        let key: String
        let field: JSONField
        var id: String { key }
    }

    private func refresh() async {
        isLoading = true
        defer { isLoading = false }
        do {
            export = try await model.loadConfig()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// `file`: one allowlisted path.  The client refuses anything outside the
/// allowlist before it is sent, and the device enforces it again.
struct FileScreen: View {
    @EnvironmentObject private var model: AppModel
    @State private var path = "/etc/issue"
    @State private var content: FileContent?
    @State private var error: String?
    @State private var isLoading = false

    var body: some View {
        Form {
            Section {
                Picker("Known file", selection: $path) {
                    ForEach(FileAllowlist.suggestedPaths, id: \.self) { path in
                        Text(path).tag(path)
                    }
                }
                TextField("Path", text: $path)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button {
                    Task { await load() }
                } label: {
                    Label("Read file", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(!FileAllowlist.isAllowed(path) || isLoading)
            } footer: {
                Text("Only /etc/issue, /tmp/FirmwareUpdateState.json and files below /log can be read.")
            }

            if let error { Section { ErrorBanner(message: error) } }

            if let content {
                Section("\(content.path) · \(content.encoding.rawValue) · \(content.byteCount) bytes") {
                    ScrollView(.horizontal) {
                        Text(content.content)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }
        }
        .navigationTitle("Files")
    }

    private func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            content = try await model.loadFile(path)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}
