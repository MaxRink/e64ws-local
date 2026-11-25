package de.mahlkoenig.e64local.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import de.mahlkoenig.e64local.R
import de.mahlkoenig.e64local.core.StringRow

private val logKinds = listOf(
    Triple("grind_log", R.string.logs_grind, "grind_date_time"),
    Triple("service_log", R.string.logs_service, "event_date_time"),
    Triple("alert_log", R.string.logs_alert, "alert_date_time"),
)

/** Grind, service and alert history with pagination and time filters. */
@Composable
fun LogsScreen(viewModel: AppViewModel) {
    val state by viewModel.logs.collectAsState()
    var since by remember { mutableStateOf(state.since) }
    var until by remember { mutableStateOf(state.until) }

    LaunchedEffect(Unit) {
        if (state.page == null && !state.loading) viewModel.loadLogs("grind_log")
    }

    ScreenColumn {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            logKinds.forEach { (kind, labelRes, _) ->
                FilterChip(
                    selected = state.kind == kind,
                    onClick = {
                        viewModel.loadLogs(kind, since, until)
                    },
                    label = { Text(stringResource(labelRes)) },
                )
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = since,
                onValueChange = { since = it },
                label = { Text(stringResource(R.string.logs_since)) },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            OutlinedTextField(
                value = until,
                onValueChange = { until = it },
                label = { Text(stringResource(R.string.logs_until)) },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
        }

        Button(onClick = { viewModel.loadLogs(state.kind, since, until) }, enabled = !state.loading) {
            Text(stringResource(R.string.logs_apply))
        }

        val page = state.page
        if (page != null) {
            Text(
                "${page.rows.size} rows · offset ${page.offset} · limit ${page.limit}",
                style = MaterialTheme.typography.labelMedium,
            )
            if (page.note != null) {
                NoticeCard("Note", page.note)
            }
            page.rows.forEach { row -> RowCard(row) }
            if (page.rows.isEmpty()) {
                Text(stringResource(R.string.logs_empty), style = MaterialTheme.typography.bodyMedium)
            }
            if (page.hasMore) {
                Text(stringResource(R.string.logs_more_hint), style = MaterialTheme.typography.bodySmall)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { viewModel.shiftLogsPage(forward = false) }, enabled = page.offset > 0) {
                    Text(stringResource(R.string.logs_prev))
                }
                Button(onClick = { viewModel.shiftLogsPage(forward = true) }, enabled = page.hasMore) {
                    Text(stringResource(R.string.logs_next))
                }
            }
        }

        if (state.error != null) {
            ErrorCard(state.error.orEmpty()) { viewModel.clearError() }
        }
    }
}

@Composable
fun RowCard(row: StringRow) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .padding(12.dp)
                .horizontalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            row.columns.forEach { (key, value) ->
                Text("$key = $value", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
        }
    }
}
