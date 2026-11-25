// Root build file. The only plugins are AGP and the Compose compiler; nothing
// here phones home, fetches from a vendor host, or adds telemetry.
//
// AGP 9 ships Kotlin support itself, so org.jetbrains.kotlin.android is
// deliberately absent; only the Compose compiler plugin is added.
plugins {
    id("com.android.application") version "9.5.3" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}
