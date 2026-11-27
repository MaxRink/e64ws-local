# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# Android target: JDK 21 + Android SDK platform 37.2 + build-tools 36.0.0 + Gradle 9.9.2.
#
# The package list is the one this build actually asks for, and it was measured,
# not guessed.  apps/android compiles against compileSdk 37 / compileSdkMinor 2
# with AGP 9.5.3 (apps/android/app/build.gradle.kts); asked what it resolves
# those two numbers to, AGP 9.5.3 answers `compileSdkVersion = android-37.2` and
# `buildToolsVersion = 36.0.0`.  Both are pinned below so the image leaves AGP
# nothing to install mid-build.  The names are not interchangeable with their
# neighbours: `platforms;android-37` is not a package sdkmanager offers at all
# (it exits 1 with "Failed to find package"), and build-tools 37.0.0 is a real
# package but the wrong one - AGP would still fetch 36.0.0 on the first build.
#
# What is verified: the image was built on 2026-11-26 (linux/arm64, with the JDK
# pin from docker/images.env) in a real `docker build` that completed all six
# layers, so the commandline-tools download, the licence acceptance, the
# sdkmanager install of exactly the three packages below and the handover to the
# unprivileged user are measured, not assumed.  Verified inputs: the JDK base
# image digest (docker/images.env) and Gradle 9.9.2 (read from the wrapper
# properties in this repository).
#
# What is NOT verified: the Gradle/Maven build itself.  The wrapper pins Gradle
# 9.9.2 (apps/android/gradle/wrapper/gradle-wrapper.properties) and :app needs
# that distribution plus the whole dependency graph - a network-bound download of
# hundreds of megabytes that was not run here, so the CMD is unproven.
#
# Unverified input: the SHA-256 of the commandline-tools zip.  Set
# CMDLINE_TOOLS_SHA256 to enable the checksum gate; while it stays "UNVERIFIED"
# the build prints a warning instead of silently trusting the download.  The zip
# name is verified - the layer below downloaded it under exactly that name.
#
# Build (performed; see docs/REPRODUCIBLE_BUILDS.md §6):
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
ARG ANDROID_PLATFORM=android-37.2
ARG ANDROID_BUILD_TOOLS=36.0.0

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
# as root above, so they are handed over here.
#
# The user is the base image's own `ubuntu` (uid 1000), not a fresh `gradle`.
# This file used to create `gradle` with `--uid 1000`, and that line cannot run:
# eclipse-temurin:21-jdk already ships `ubuntu` at 1000, so useradd exits 4 with
# "UID 1000 is not unique".  A free uid is the other way out and it is the wrong
# one, because uid 1000 is a repository-wide assumption: five of the six enabled
# images run as a uid-1000 user, docs/REPRODUCIBLE_BUILDS.md §2.4 requires the
# mounted tree to be readable by uid 1000, and `verify.sh --clean` chmods its own
# export `a+rX` to satisfy exactly that.  A build writing as uid 1500 would hand
# a workspace back owned by a stranger on Linux - the problem this layer exists
# to prevent.  Reusing the base's uid is also the precedent `e64-node:26` sets
# (docker/node/Dockerfile:25-28, `USER node`), and it is a fixed fact rather than
# a race because docker/images.env pins the base by digest.  `ubuntu` is in the
# `sudo` group there; sudo is not installed in this image, so that grants nothing.
RUN mkdir -p /opt/gradle-home \
    && chown -R ubuntu:ubuntu /opt/android-sdk /opt/gradle-home

USER ubuntu

WORKDIR /src
CMD ["./gradlew", "--version"]
