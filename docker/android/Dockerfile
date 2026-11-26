# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# Android target: JDK 21 + Android SDK platform 37.2 + build-tools + Gradle 9.9.2.
#
# Why this file is a declaration and not a verified build: apps/android
# compiles against compileSdk 37 / compileSdkMinor 2 with AGP 9.5.3
# (apps/android/build.gradle.kts) and the wrapper pins Gradle 9.9.2
# (apps/android/gradle/wrapper/gradle-wrapper.properties).  Reproducing that
# needs the Android SDK, which only arrives through sdkmanager behind a licence
# prompt, plus a Gradle distribution and the whole Maven dependency graph - a
# multi-gigabyte, network-bound build.  It was deliberately not run here.
#
# Verified inputs: the JDK base image digest (docker/images.env) and Gradle
# 9.9.2 (read from the wrapper properties in this repository).
# UNVERIFIED inputs: the commandline-tools zip name and its SHA-256, and the
# sdkmanager package names for platform 37 / build-tools 37. Nothing below was
# downloaded.  Set CMDLINE_TOOLS_SHA256 to enable the checksum gate; while it
# stays "UNVERIFIED" the build prints a warning instead of silently trusting the
# download.
#
# Build (not performed):
#   docker build -f docker/android/Dockerfile \
#     --build-arg JDK_IMAGE=eclipse-temurin:21-jdk@sha256:... \
#     --build-arg CMDLINE_TOOLS_SHA256=<sha256 of the zip> \
#     -t e64-android docker
#   docker run --rm -v "$PWD/apps/android:/src" -w /src e64-android ./gradlew --version

ARG JDK_IMAGE
FROM ${JDK_IMAGE}

ENV ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_HOME=/opt/android-sdk \
    GRADLE_USER_HOME=/opt/gradle-home \
    PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:${PATH}

ARG CMDLINE_TOOLS=commandlinetools-linux-13114758_latest.zip
ARG CMDLINE_TOOLS_SHA256=UNVERIFIED
ARG ANDROID_PLATFORM=android-37
ARG ANDROID_BUILD_TOOLS=37.0.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# The checksum gate is the point of this layer: a downloaded toolchain that is
# never hashed is a supply-chain hole dressed up as reproducibility.
RUN set -eu; \
    url="https://dl.google.com/android/repository/${CMDLINE_TOOLS}"; \
    curl -fsSL -o /tmp/cmdline-tools.zip "$url"; \
    if [ "$CMDLINE_TOOLS_SHA256" = "UNVERIFIED" ]; then \
        echo "WARNING: CMDLINE_TOOLS_SHA256 is not set; the Android toolchain was not verified" >&2; \
    else \
        echo "${CMDLINE_TOOLS_SHA256}  /tmp/cmdline-tools.zip" | sha256sum -c -; \
    fi; \
    mkdir -p /opt/android-sdk/cmdline-tools; \
    unzip -q /tmp/cmdline-tools.zip -d /opt/android-sdk/cmdline-tools; \
    rm /tmp/cmdline-tools.zip; \
    mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest

# Licences are accepted non-interactively; this is the step that makes the image
# usable for a later, unmetered build.
RUN yes | sdkmanager --sdk_root=/opt/android-sdk --licenses >/dev/null \
    && sdkmanager --sdk_root=/opt/android-sdk --install \
        "platforms;${ANDROID_PLATFORM}" \
        "build-tools;${ANDROID_BUILD_TOOLS}" \
        "platform-tools"

# Build unprivileged.  A Gradle build writes into GRADLE_USER_HOME and into the
# project's build/ directory; doing that as root is how a mounted source tree
# ends up with root-owned artifacts.  The SDK and the Gradle home are installed
# as root above, so they are handed over here.  UNVERIFIED, like the rest of this
# file: the image was never built (see docs/REPRODUCIBLE_BUILDS.md §6), so this
# ownership change has not been executed.
RUN useradd --create-home --uid 1000 --user-group gradle \
    && mkdir -p /opt/gradle-home \
    && chown -R gradle:gradle /opt/android-sdk /opt/gradle-home

USER gradle

WORKDIR /src
CMD ["./gradlew", "--version"]
