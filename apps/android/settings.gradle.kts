pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

// Keep the build cache inside this checkout instead of in the Gradle user home.
//
// AGP 9.5.3's :app:mergeDebugResources entry cannot be carried between
// checkouts: its key does not depend on the absolute path, but the entry stores
// this checkout's own resource directories, so an entry written by one checkout
// is restored verbatim into another. When such an entry is wrong, the merge
// publishes only the app's own resources and :app:processDebugResources fails
// with AAPT "not found" errors for symbols androidx.core declares itself
// (drawable/notification_action_background.xml and the compat dimens and styles
// it references). That reads as a missing AppCompat dependency and is not one:
// nothing in app/src uses AppCompat. How an entry reaches that state is not
// established; that entries do travel between checkouts is.
//
// Scoping the cache here keeps every other task cached, merge resources
// included, and stops another checkout's entries from being restored here.
// That is the guarantee, not that an entry can never travel: a tree that carries
// its .gradle with it - copied or moved - restores its own entries, merge
// included. .gradle/ is already ignored.
//
// Repairing a tree that restored a bad entry means making the merge run again:
// `./gradlew --rerun-tasks`, which also overwrites the entry with a good one, or
// deleting .gradle/build-cache AND app/build and rebuilding. `clean` alone does
// not help - the merge is restored from the cache again - and --no-build-cache
// only helps together with a clean, leaving the bad entry in place for the next
// cached build.
//
// Remove this once an AGP upgrade stops storing checkout-specific paths in that
// entry; README.md carries the check that decides it, and the cache can then go
// back to the Gradle user home.
buildCache {
    local {
        directory = File(rootDir, ".gradle/build-cache")
    }
}

rootProject.name = "e64local"
include(":app")
