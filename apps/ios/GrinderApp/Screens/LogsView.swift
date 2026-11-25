import SwiftUI
import GrinderCore

/// Screen 3 — Logs: `grind_log`, `service_log`, `alert_log` with pagination and
/// time filters, newest first.
struct LogsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var kind: LogKind = .grind
    @State private var since = ""
    @State private var until = ""

    var body: some View {
        NavigationStack {
            LogListView(kind: kind, since: since, until: until)
                .navigationTitle("Logs")
                .toolbar {
                    ToolbarItem(placement: .principal) {
                        Picker("Log", selection: $kind) {
                            ForEach(LogKind.allCases) { kind in
                                Text(kind.title).tag(kind)
                            }
                        }
                        .pickerStyle(.segmented)
                    }
                }
                .safeAreaInset(edge: .top) {
                    filterBar
                }
        }
    }

    private var filterBar: some View {
        HStack(spacing: 8) {
            TextField("Since (YYYY-MM-DD)", text: $since)
                .textFieldStyle(.roundedBorder)
                .keyboardType(.numbersAndPunctuation)
            TextField("Until", text: $until)
                .textFieldStyle(.roundedBorder)
                .keyboardType(.numbersAndPunctuation)
        }
        .font(.footnote)
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.bar)
    }
}

/// One log route, with a stable page walk (docs/LOCAL_API.md §5).
struct LogListView: View {
    @EnvironmentObject private var model: AppModel
    let kind: LogKind
    let since: String
    let until: String

    @State private var rows: [Row] = []
    @State private var page: LogPage?
    @State private var error: String?
    @State private var isLoading = false
    @State private var offset = 0

    private static let pageSize = 100

    var body: some View {
        List {
            if let error {
                Section { ErrorBanner(message: error) }
            }
            if let note = page?.note {
                Section { Text(note).font(.footnote).foregroundStyle(.secondary) }
            }
            ForEach(rows) { row in
                NavigationLink {
                    RowDetailView(title: kind.title, row: row)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.primaryText(for: kind)).font(.headline)
                        Text(row.secondaryText(for: kind))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if page?.hasMore == true {
                Button {
                    Task { await load(append: true) }
                } label: {
                    Label("Load more", systemImage: "arrow.down.circle")
                }
                .disabled(isLoading)
            }
            if rows.isEmpty && !isLoading && error == nil {
                Text("No rows for this range.")
                    .foregroundStyle(.secondary)
            }
        }
        .overlay { if isLoading && rows.isEmpty { ProgressView() } }
        .refreshable { await load(append: false) }
        .task(id: "\(kind.rawValue)|\(since)|\(until)") { await load(append: false) }
    }

    private func load(append: Bool) async {
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let query = try LogQuery(
                limit: Self.pageSize,
                offset: append ? offset : 0,
                since: since,
                until: until
            )
            let page = try await model.loadLog(kind, query: query)
            self.page = page
            self.offset = page.nextOffset
            rows = append ? rows + page.rows : page.rows
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

extension Row {
    /// The column that identifies a row, per log type.
    func primaryText(for kind: LogKind) -> String {
        switch kind {
        case .grind:
            return self["grind_date_time"] ?? self["grind_id"] ?? "Grind"
        case .service:
            return self["event_type"] ?? self["event_date_time"] ?? "Event"
        case .alert:
            return self["alert_type"] ?? self["alert_date_time"] ?? "Alert"
        }
    }

    func secondaryText(for kind: LogKind) -> String {
        switch kind {
        case .grind:
            let weight = self["grind_weight"].flatMap { Int($0) }.map { String(format: "%.1f g", Double($0) / 1000) } ?? "–"
            let mode = self["recipe_mode"] ?? "–"
            let success = self["grind_successfull"] == "1" ? "ok" : "failed"
            return "\(mode) · \(weight) · \(success)"
        case .service:
            return self["event_date_time"] ?? self["event_id"] ?? ""
        case .alert:
            let active = self["alert_active"] == "1" ? "active" : "cleared"
            return "\(self["alert_date_time"] ?? "") · \(active)"
        }
    }
}

/// Every column of one row, as returned — values are strings by contract.
struct RowDetailView: View {
    let title: String
    let row: Row

    var body: some View {
        List {
            ForEach(row.orderedColumns, id: \.self) { column in
                InfoRow(label: column, value: row[column] ?? "", monospaced: true)
            }
        }
        .navigationTitle(title)
    }
}
