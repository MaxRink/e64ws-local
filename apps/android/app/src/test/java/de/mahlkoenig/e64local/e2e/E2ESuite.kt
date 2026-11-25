package de.mahlkoenig.e64local.e2e

import org.junit.Test

/**
 * The live end-to-end suite: the app's real networking and action code against
 * the repository's own simulator (`tools/e64ws_simulator.py`).
 *
 * Inputs (see `apps/android/README.md`):
 *  - `E64_E2E_BASE_URL` — required; the simulator's plain-http address,
 *    e.g. `http://127.0.0.1:18787`. Unset means the suite prints
 *    `E2E SKIP (no E64_E2E_BASE_URL)` and runs nothing.
 *  - `E64_E2E_TOKEN` — required once the address is set; the local-API owner
 *    token (`sim-local-api-token` for the bundled simulator).
 *  - `E64_E2E_PASSWORD` — optional, defaults to `sim-password`.
 *
 * Exactly one summary line is printed: `E2E PASS <n>` on success (with `n` the
 * number of checks that ran) or `E2E FAIL <detail>` on stderr.
 *
 * The simulator is expected to run with `--enable-actions`; the action block
 * fails with a message naming the flag when the gate is still closed.
 */
class E2ESuite {

    @Test
    fun `live simulator end to end`() {
        val baseUrl = System.getenv(E2EEnvironment.BASE_URL)?.trim().orEmpty()
        if (baseUrl.isEmpty()) {
            println(E2EReport.SKIP_LINE)
            return
        }

        val report = E2EReport()
        try {
            val target = E2EEnvironment.parseBaseUrl(baseUrl)
            val token = E2EEnvironment.read(E2EEnvironment.TOKEN)
                ?: throw E2EFailure(
                    "${E2EEnvironment.TOKEN} is empty. The simulator's local-API token is " +
                        "'${E2EEnvironment.DEFAULT_API_TOKEN}'; its --token flag is a different, " +
                        "WSS-only test token and is not this credential.",
                )
            val password = E2EEnvironment.read(E2EEnvironment.PASSWORD) ?: E2EEnvironment.DEFAULT_PASSWORD

            SimulatorClient(target, token, password).use { device ->
                LiveDeviceChecks(report, device, token, password).run()
                ActionLifecycleChecks(report, device, token).run()
            }
            report.emitSuccess()
        } catch (failure: E2EFailure) {
            report.emitFailure(failure.message ?: "unknown failure")
            throw AssertionError("E2E FAIL ${failure.message}")
        } catch (throwable: Throwable) {
            report.emitFailure(E2EReport.oneLine(throwable))
            throw AssertionError("E2E FAIL ${E2EReport.oneLine(throwable)}")
        }
    }
}
