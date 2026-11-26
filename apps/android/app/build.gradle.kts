import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The bundled PHP module must be byte-identical to the repository copy. The
// expected digest is read from the asset itself, and the copy shipped in
// apps/android/app/src/main/assets is checked against it on every build.
val phpModuleAsset = layout.projectDirectory.file("src/main/assets/rest_api_dev.php")

android {
    namespace = "de.mahlkoenig.e64local"
    compileSdk = 37
    // The Compose BOM now resolves Compose 1.13.x, whose AAR metadata requires
    // compiling against API 37.1 or later; 37.2 is the current minor release.
    // This only raises the APIs visible to the compiler - targetSdk stays 36.
    compileSdkMinor = 2

    defaultConfig {
        applicationId = "de.mahlkoenig.e64local"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        unitTests {
            // org.json is stubbed out in the android.jar the compiler uses, so
            // the JVM tests supply the real artifact instead (see build.gradle.kts
            // dependencies). Nothing here runs on a device or an emulator.
            isIncludeAndroidResources = false
            isReturnDefaultValues = true
        }
    }

    lint {
        abortOnError = false
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

// Fail the build when a bundled PHP asset drifts from the checked-in copy in
// ondevice/. This is the build-time half of the integrity check; app/src/test
// asserts the same digests again on the JVM. Both files are bundled: the
// module is the API, the runner is the root-owned action helper it expects.
//
// The digest is computed with MessageDigest directly inside doLast: a helper
// function declared at script level would make the task action capture the
// build script instance, which the configuration cache refuses to serialize.
val verifyBundledModule by tasks.registering {
    group = "verification"
    description = "Assert the bundled PHP files match their ondevice/ copies"
    val assets = listOf(
        phpModuleAsset to rootProject.projectDir.resolve("../../ondevice/rest_api_dev.php"),
        layout.projectDirectory.file("src/main/assets/e64local_action_run.php") to
            rootProject.projectDir.resolve("../../ondevice/e64local_action_run.php"),
    )
    outputs.upToDateWhen { false }
    doLast {
        val digest = MessageDigest.getInstance("SHA-256")
        for ((asset, source) in assets) {
            val name = source.name
            require(source.isFile) {
                "cannot find ondevice/$name at ${source.absolutePath}"
            }
            val assetBytes = asset.asFile.readBytes()
            val sourceBytes = source.readBytes()
            val assetDigest = digest.digest(assetBytes).joinToString("") { "%02x".format(it) }
            val sourceDigest = digest.digest(sourceBytes).joinToString("") { "%02x".format(it) }
            check(assetDigest == sourceDigest) {
                "bundled $name (sha256=$assetDigest) differs from " +
                    "ondevice/$name (sha256=$sourceDigest). Copy the " +
                    "repository file into the asset before building."
            }
        }
    }
}

tasks.named("preBuild") { dependsOn(verifyBundledModule) }

// The live end-to-end suite (app/src/test/java/de/mahlkoenig/e64local/e2e) reports
// its result as one summary line on stdout, which Gradle otherwise swallows.
// Standard streams are forwarded unchanged; no other test prints anything.
//
// The suite is configured through the environment, so a change of address has
// to invalidate the task result instead of silently reporting a previous run.
// Credentials are deliberately not recorded as task inputs: the task always
// runs (see below), and any fingerprint of a credential is still a derivative
// of it, which is not worth writing to disk.
val e2eEnvironment = providers
tasks.withType<Test>().configureEach {
    if (name == "testDebugUnitTest") {
        testLogging { showStandardStreams = true }
        // The live suite's contract is one summary line per invocation. A cached
        // "up-to-date" result would report nothing at all, and the simulator it
        // talks to is not a declared input, so the task always runs.
        outputs.upToDateWhen { false }
        inputs.property(
            "e2e.baseUrl",
            e2eEnvironment.environmentVariable("E64_E2E_BASE_URL").orElse(""),
        )
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.11.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    // Only the core icon set is used for the bottom navigation.
    implementation("androidx.compose.material:material-icons-core")

    // Real org.json for the JVM tests; android.jar only stubs it.
    testImplementation("org.json:json:20260814")
    testImplementation("junit:junit:4.13.2")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
