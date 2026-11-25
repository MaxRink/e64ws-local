package de.mahlkoenig.e64local.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import de.mahlkoenig.e64local.R

/** Machine identity and the capability handshake for the configured device. */
@Composable
fun DashboardContent(viewModel: AppViewModel, state: DashboardUi) {
    SectionTitle(stringResource(R.string.dashboard_connection))

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            KeyValueRow("Device", state.endpoint.ifEmpty { "—" })
            KeyValueRow(stringResource(R.string.dashboard_model), state.machine?.model ?: "—")
            KeyValueRow(stringResource(R.string.dashboard_variant), state.machine?.variant ?: "—")
            KeyValueRow(stringResource(R.string.dashboard_firmware), state.machine?.firmware ?: "—")
            KeyValueRow(stringResource(R.string.dashboard_devmode), if (state.machine?.devMode == true) "yes" else "no")
        }
    }

    val serial = state.machine?.serialSha256
    if (serial != null) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.dashboard_serial), style = MaterialTheme.typography.labelLarge)
                MonoBlock(serial)
                Text(stringResource(R.string.dashboard_serial_note), style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    val capabilities = state.capabilities
    if (capabilities != null) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                KeyValueRow(stringResource(R.string.dashboard_api_version), capabilities.apiVersion)
                KeyValueRow("Pagination", if (capabilities.pagination) "yes" else "no")
                KeyValueRow("Time filters", if (capabilities.timeFilters) "yes" else "no")
                KeyValueRow("Actions", if (capabilities.actionsEnabled) "enabled" else "disabled")
                KeyValueRow("Max rows", capabilities.maxRows.toString())
                Text(
                    stringResource(R.string.dashboard_routes) + ": " + capabilities.routes.sorted().joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }

    if (state.error != null) {
        ErrorCard(state.error) { viewModel.clearError() }
    }

    Button(onClick = { viewModel.refresh() }, enabled = !state.loading, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.dashboard_refresh))
    }

    OutlinedButton(onClick = { viewModel.openSetup() }, modifier = Modifier.fillMaxWidth()) {
        Text("Re-run setup")
    }
}
