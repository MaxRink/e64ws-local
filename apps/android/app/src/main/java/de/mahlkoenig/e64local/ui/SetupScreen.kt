package de.mahlkoenig.e64local.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import de.mahlkoenig.e64local.R
import de.mahlkoenig.e64local.device.PinnedTrustManager

/**
 * The setup wizard. Its only job is to take an address, probe the device and
 * then run the one-click install after the owner has seen the exact commands.
 */
@Composable
fun DashboardScreen(viewModel: AppViewModel) {
    val dashboard by viewModel.dashboard.collectAsState()
    val setup by viewModel.setup.collectAsState()
    val setupOpen by viewModel.setupOpen.collectAsState()

    LaunchedEffect(Unit) {
        if (viewModel.activeEndpointId != null && !dashboard.connected && !dashboard.loading) {
            viewModel.refresh()
        }
    }

    ScreenColumn {
        if (viewModel.activeEndpointId == null || setupOpen) {
            SetupWizard(viewModel, setup)
            if (setupOpen) {
                OutlinedButton(onClick = { viewModel.closeSetup() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Back to dashboard")
                }
            }
        } else {
            DashboardContent(viewModel, dashboard)
            if (setup is SetupUi.Done) {
                NoticeCard(
                    stringResource(R.string.setup_success),
                    "The owner token is stored encrypted on this phone.",
                )
            }
        }
    }
}

@Composable
private fun SetupWizard(viewModel: AppViewModel, setup: SetupUi) {
    var host by remember { mutableStateOf(viewModel.activeEndpointId ?: "") }
    var password by remember { mutableStateOf("") }

    SectionTitle(stringResource(R.string.setup_title))
    OutlinedTextField(
        value = host,
        onValueChange = { host = it },
        label = { Text(stringResource(R.string.setup_host_label)) },
        placeholder = { Text(stringResource(R.string.setup_host_hint)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = password,
        onValueChange = { password = it },
        label = { Text(stringResource(R.string.setup_password_label)) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
    )

    when (setup) {
        is SetupUi.CertificateNeeded -> {
            NoticeCard(stringResource(R.string.setup_trust_title), setup.reason)
            MonoBlock("SHA-256: " + PinnedTrustManager.displayFingerprint(setup.certificate.sha256))
            MonoBlock("Subject: " + setup.certificate.subject)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { viewModel.trustCertificate(host, setup.certificate, password) }) {
                    Text(stringResource(R.string.setup_trust_yes))
                }
                OutlinedButton(onClick = { viewModel.dismissSetupError() }) {
                    Text(stringResource(R.string.setup_trust_no))
                }
            }
        }

        is SetupUi.Probed -> {
            val report = setup.report
            if (!report.fingerprint.devMode) {
                NoticeCard("Development mode", stringResource(R.string.setup_devmode_warning))
            }
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    KeyValueRow(stringResource(R.string.dashboard_model), report.fingerprint.model.ifEmpty { "unknown" })
                    KeyValueRow(stringResource(R.string.dashboard_firmware), report.fingerprint.firmware.ifEmpty { "unknown" })
                    KeyValueRow(stringResource(R.string.dashboard_devmode), if (report.fingerprint.devMode) "yes" else "no")
                }
            }
            if (report.alreadyInstalled) {
                NoticeCard("Local API present", "This device already answers the local API. Install again to rotate the owner token.")
            }
            Button(onClick = { viewModel.prepareInstall(host, password) }) {
                Text(stringResource(R.string.setup_install))
            }
        }

        is SetupUi.Confirming -> {
            ConfirmPlanCard(setup.plan) { viewModel.runInstall(host, password) }
        }

        is SetupUi.Running -> {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(setup.progress.detail, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        is SetupUi.Failed -> ErrorCard(setup.message) { viewModel.dismissSetupError() }
        is SetupUi.Done -> NoticeCard(stringResource(R.string.setup_success), "Open the Dashboard tab to read the machine identity.")
        SetupUi.Idle -> Unit
    }

    if (setup is SetupUi.Idle || setup is SetupUi.Failed) {
        Button(onClick = { viewModel.probe(host, password) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.setup_probe))
        }
    }
}

@Composable
private fun ConfirmPlanCard(plan: de.mahlkoenig.e64local.setup.SetupPlan, onConfirm: () -> Unit) {
    var acknowledged by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.setup_confirm_title), style = MaterialTheme.typography.titleSmall)
            Text(
                "These ${plan.commandCount} commands run as root on your grinder. " +
                    "They install the local API module, the root-owned action runner and " +
                    "create a new owner token. Actions stay disabled until a policy file " +
                    "is deployed. Nothing else is written: no ESP, no firmware, no database.",
                style = MaterialTheme.typography.bodySmall,
            )
            SectionTitle("Installer script")
            Text(
                plan.installerScript,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 260.dp)
                    .verticalScroll(rememberScrollState())
                    .horizontalScroll(rememberScrollState()),
            )
            SectionTitle("Upload and install commands")
            Text(
                (plan.moduleUploadCommands + plan.runnerUploadCommands + plan.installerCommands).joinToString("\n"),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 220.dp)
                    .verticalScroll(rememberScrollState())
                    .horizontalScroll(rememberScrollState()),
            )
            Text(
                "Module SHA-256: ${plan.moduleSha256} (${plan.moduleBytes} bytes)",
                style = MaterialTheme.typography.labelSmall,
            )
            Text(
                "Runner SHA-256: ${plan.runnerSha256} (${plan.runnerBytes} bytes)",
                style = MaterialTheme.typography.labelSmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { acknowledged = !acknowledged }) {
                    Text(if (acknowledged) "Command list reviewed ✓" else "I have read the commands")
                }
                Button(onClick = onConfirm, enabled = acknowledged) {
                    Text(stringResource(R.string.setup_confirm_run))
                }
            }
        }
    }
}
