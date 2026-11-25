package de.mahlkoenig.e64local.setup

/**
 * Reads the bundled PHP module. Injected so the setup coordinator and the
 * tests can supply bytes without touching the Android asset framework.
 */
fun interface ModuleProvider {
    fun read(): ByteArray
}
