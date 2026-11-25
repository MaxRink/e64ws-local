package de.mahlkoenig.e64local.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import de.mahlkoenig.e64local.R

/** Explains the owner-token model, the dev-mode requirement and the no-cloud stance. */
@Composable
fun AboutScreen() {
    ScreenColumn {
        SectionTitle(stringResource(R.string.about_title))
        NoticeCard(stringResource(R.string.app_name), stringResource(R.string.about_body))
        NoticeCard(stringResource(R.string.about_token_title), stringResource(R.string.about_token_body))
        NoticeCard(stringResource(R.string.about_tls_title), stringResource(R.string.about_tls_body))
        NoticeCard(stringResource(R.string.about_actions_title), stringResource(R.string.about_actions_body))
        NoticeCard(stringResource(R.string.about_devmode_title), stringResource(R.string.about_devmode_body))
        NoticeCard(stringResource(R.string.about_esp_title), stringResource(R.string.about_esp_body))
    }
}
