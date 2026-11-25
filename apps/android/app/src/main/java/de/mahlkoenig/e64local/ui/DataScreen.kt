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
import de.mahlkoenig.e64local.device.AllowedPaths

private enum class DataView(val labelRes: Int) {
    RECIPES(R.string.data_recipes),
    PORTAFILTERS(R.string.data_portafilters),
    SETTINGS(R.string.data_settings),
    CONFIG(R.string.data_config),
    FILE(R.string.data_file),
}

/** Recipes, portafilters, settings, config and the allowlisted file reader. */
@Composable
fun DataScreen(viewModel: AppViewModel) {
    val state by viewModel.data.collectAsState()
    var view by remember { mutableStateOf(DataView.RECIPES) }
    var path by remember { mutableStateOf(state.filePath) }

    LaunchedEffect(Unit) {
        if (!state.loading && state.recipes.isEmpty()) viewModel.loadData()
    }

    ScreenColumn {
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            DataView.entries.forEach { entry ->
                FilterChip(
                    selected = view == entry,
                    onClick = { view = entry },
                    label = { Text(stringResource(entry.labelRes)) },
                )
            }
        }

        when (view) {
            DataView.RECIPES -> {
                state.recipes.forEach { RowCard(it) }
                if (state.recipes.isEmpty()) Text(stringResource(R.string.logs_empty))
            }

            DataView.PORTAFILTERS -> {
                state.portafilters.forEach { RowCard(it) }
                if (state.portafilters.isEmpty()) Text(stringResource(R.string.logs_empty))
            }

            DataView.SETTINGS -> KeyValueCard(state.settings, state.settingsRedacted)
            DataView.CONFIG -> KeyValueCard(state.config, state.configRedacted)

            DataView.FILE -> {
                OutlinedTextField(
                    value = path,
                    onValueChange = { path = it },
                    label = { Text(stringResource(R.string.data_file_path_label)) },
                    singleLine = true,
                    isError = !AllowedPaths.isAllowed(path),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    AllowedPaths.suggestions.forEach { suggestion ->
                        FilterChip(
                            selected = path == suggestion,
                            onClick = { path = suggestion },
                            label = { Text(suggestion, style = MaterialTheme.typography.labelSmall) },
                        )
                    }
                }
                Button(
                    onClick = { viewModel.readFile(path) },
                    enabled = AllowedPaths.isAllowed(path) && !state.loading,
                ) { Text(stringResource(R.string.data_file_read)) }
                if (state.fileContent.isNotEmpty()) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp).horizontalScroll(rememberScrollState())) {
                            Text("encoding: ${state.fileEncoding}", style = MaterialTheme.typography.labelSmall)
                            Text(
                                state.fileContent,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                }
            }
        }

        if (state.error != null) {
            ErrorCard(state.error.orEmpty()) { viewModel.clearError() }
        }
    }
}

@Composable
private fun KeyValueCard(values: Map<String, String>, redacted: List<String>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            values.toSortedMap().forEach { (key, value) -> KeyValueRow(key, value) }
            if (values.isEmpty()) Text(stringResource(R.string.logs_empty))
            if (redacted.isNotEmpty()) {
                Text(
                    stringResource(R.string.data_redacted) + ": " + redacted.joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
