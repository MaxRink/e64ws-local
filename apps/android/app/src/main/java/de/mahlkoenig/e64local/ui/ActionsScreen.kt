package de.mahlkoenig.e64local.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import de.mahlkoenig.e64local.R
import de.mahlkoenig.e64local.device.ActionAuditRow
import de.mahlkoenig.e64local.device.ActionCatalogEntry
import de.mahlkoenig.e64local.device.ActionPolicy
import de.mahlkoenig.e64local.device.ActionSubmit
import de.mahlkoenig.e64local.device.ActionParams

/**
 * The gated action layer: catalog, prepare, confirm, status/cancel, audit.
 *
 * The screen can show a route it may not submit: the catalog is readable even
 * when the gate is closed, and a destructive entry stays visible with the
 * device's own reason and a disabled button. Nothing here invents a permission
 * the device did not report.
 */
@Composable
fun ActionsScreen(viewModel: AppViewModel) {
    val state by viewModel.actions.collectAsState()

    LaunchedEffect(Unit) {
        if (state.policy == null && !state.busy) viewModel.loadActions()
    }

    ScreenColumn {
        val policy = state.policy
        SectionTitle(stringResource(R.string.actions_title))
        GateCard(policy, state.busy, onRefresh = { viewModel.loadActions() })

        SectionTitle(stringResource(R.string.actions_catalog))
        if (policy == null) {
            Text(stringResource(R.string.actions_empty), style = MaterialTheme.typography.bodySmall)
        } else {
            policy.catalog.forEach { entry ->
                CatalogCard(
                    entry = entry,
                    selected = entry.route == state.selectedRoute,
                    onClick = { viewModel.selectActionRoute(entry.route) },
                )
            }
        }

        if (state.selectedRoute.isNotEmpty()) {
            PrepareCard(state, viewModel)
        }

        if (state.activeActionId != null) {
            StatusCard(state, viewModel)
        }

        AuditCard(state, viewModel)

        state.message?.let { text ->
            NoticeCard(title = stringResource(R.string.actions_notice_title), body = text)
        }
        state.error?.let { message ->
            ErrorCard(message) { viewModel.clearActionNotice() }
        }
    }

    state.pending?.let { pending ->
        AlertDialog(
            onDismissRequest = { viewModel.dismissActionConfirm() },
            title = { Text(stringResource(R.string.actions_confirm_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    KeyValueRow(stringResource(R.string.actions_route), pending.actionRoute)
                    KeyValueRow(stringResource(R.string.actions_risk), state.pendingRisk)
                    Text(
                        stringResource(R.string.actions_params),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    MonoBlock(state.paramsText.trim().ifBlank { ActionParams.EMPTY })
                    KeyValueRow(stringResource(R.string.actions_expires), pending.expiresAt)
                    if (pending.warnings.isNotEmpty()) {
                        KeyValueRow(
                            stringResource(R.string.actions_warnings),
                            pending.warnings.joinToString("; "),
                        )
                    }
                    Text(
                        stringResource(R.string.actions_confirm_note),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { viewModel.runConfirmedAction() }) {
                    Text(stringResource(R.string.actions_confirm_run))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissActionConfirm() }) {
                    Text(stringResource(R.string.actions_confirm_cancel))
                }
            },
        )
    }
}

@Composable
private fun GateCard(policy: ActionPolicy?, busy: Boolean, onRefresh: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (policy == null) {
                Text(stringResource(R.string.actions_empty), style = MaterialTheme.typography.bodySmall)
            } else {
                KeyValueRow(
                    stringResource(R.string.actions_gate),
                    if (policy.enabled) {
                        stringResource(R.string.actions_enabled)
                    } else {
                        stringResource(R.string.actions_disabled)
                    },
                )
                KeyValueRow(
                    stringResource(R.string.actions_destructive),
                    if (policy.destructiveEnabled) {
                        stringResource(R.string.actions_allowed)
                    } else {
                        stringResource(R.string.actions_blocked)
                    },
                )
                KeyValueRow(
                    stringResource(R.string.actions_dispatchable),
                    policy.actionRoutes.size.toString(),
                )
                policy.reason?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                if (!policy.destructiveEnabled) {
                    Text(
                        stringResource(R.string.actions_destructive_off),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            OutlinedButton(onClick = onRefresh, enabled = !busy) {
                Text(stringResource(R.string.actions_refresh))
            }
        }
    }
}

@Composable
private fun CatalogCard(entry: ActionCatalogEntry, selected: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = entry.isImplemented, onClick = onClick),
        colors = if (selected) {
            CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
        } else {
            CardDefaults.cardColors()
        },
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(entry.route, style = MaterialTheme.typography.titleSmall, fontFamily = FontFamily.Monospace)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(entry.risk, style = MaterialTheme.typography.labelSmall)
                Text(entry.status, style = MaterialTheme.typography.labelSmall)
            }
            entry.summary?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            entry.blocked?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            entry.reason?.let {
                Text(
                    stringResource(R.string.actions_unavailable) + ": " + it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun PrepareCard(state: ActionsUi, viewModel: AppViewModel) {
    val gate = state.gate()
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(state.selectedRoute, style = MaterialTheme.typography.titleSmall, fontFamily = FontFamily.Monospace)
            state.policy?.entry(state.selectedRoute)?.let { entry ->
                KeyValueRow(stringResource(R.string.actions_risk), entry.risk)
            }
            OutlinedTextField(
                value = state.paramsText,
                onValueChange = viewModel::updateActionParams,
                label = { Text(stringResource(R.string.actions_params)) },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
            )
            // A blocked route keeps its explanation and a disabled button: the
            // destructive gate is visible, not hidden behind a failure toast.
            (gate as? ActionSubmit.Blocked)?.let { blocked ->
                Text(
                    blocked.reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Button(
                onClick = { viewModel.prepareAction() },
                enabled = gate == ActionSubmit.Allowed && !state.busy,
            ) { Text(stringResource(R.string.actions_prepare)) }
        }
    }
}

@Composable
private fun StatusCard(state: ActionsUi, viewModel: AppViewModel) {
    val status = state.status
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.actions_status), style = MaterialTheme.typography.titleSmall)
            KeyValueRow(stringResource(R.string.actions_action_id), state.activeActionId.orEmpty())
            if (status == null) {
                Text(stringResource(R.string.actions_empty), style = MaterialTheme.typography.bodySmall)
            } else {
                KeyValueRow(stringResource(R.string.actions_state), status.state)
                KeyValueRow(stringResource(R.string.actions_route), status.actionRoute)
                KeyValueRow(stringResource(R.string.actions_cancel_requested), status.cancelRequested.toString())
                status.startedAt?.let { KeyValueRow(stringResource(R.string.actions_started), it) }
                status.finishedAt?.let { KeyValueRow(stringResource(R.string.actions_finished), it) }
                status.durationMs?.let {
                    KeyValueRow(stringResource(R.string.actions_duration), "$it ms")
                }
                if (status.errorCode != 0 || !status.error.isNullOrBlank()) {
                    KeyValueRow(stringResource(R.string.actions_error_code), status.errorCode.toString())
                    status.error?.let { error ->
                        Text(error, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                if (status.resultJson.isNotEmpty()) {
                    Text(stringResource(R.string.actions_result), style = MaterialTheme.typography.labelLarge)
                    MonoBlock(status.resultJson)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { viewModel.refreshActionStatus() }, enabled = !state.busy) {
                    Text(stringResource(R.string.actions_status_refresh))
                }
                Button(
                    onClick = { viewModel.cancelAction() },
                    enabled = !state.busy && (status?.isCancellable ?: true),
                ) { Text(stringResource(R.string.actions_cancel)) }
            }
        }
    }
}

@Composable
private fun AuditCard(state: ActionsUi, viewModel: AppViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.actions_audit), style = MaterialTheme.typography.titleSmall)
            val page = state.audit
            if (page == null || page.rows.isEmpty()) {
                Text(stringResource(R.string.actions_empty), style = MaterialTheme.typography.bodySmall)
            } else {
                KeyValueRow(stringResource(R.string.actions_audit_total), "${page.total} (${page.limit} per page)")
                page.rows.forEach { row -> AuditRow(row) }
                Text(
                    stringResource(R.string.actions_audit_newest_first),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            OutlinedButton(onClick = { viewModel.loadActionAudit() }, enabled = !state.busy) {
                Text(stringResource(R.string.actions_audit_load))
            }
        }
    }
}

@Composable
private fun AuditRow(row: ActionAuditRow) {
    Column(modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) {
        Text(
            "${row.ts}  ${row.phase}",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
        )
        Text(
            buildString {
                append(row.route)
                if (row.errorCode != 0) append("  errorCode ").append(row.errorCode)
                if (row.retryAfter != null) append("  retryAfter ").append(row.retryAfter)
                if (row.durationMs != null) append("  ").append(row.durationMs).append(" ms")
                row.result?.let { append("  ").append(it) }
            },
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
        )
    }
}
