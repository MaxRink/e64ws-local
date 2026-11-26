# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# iOS GrinderCore on Linux: a reproducer, not a working build.
#
# Why the split into two stages: apps/ios/GrinderCore looks portable.  Every
# source file imports Foundation, `Security` is imported only behind
# `#if canImport(Security)` in TokenStore.swift and Configuration.swift, and
# Package.swift lists only iOS 17 / macOS 14, which does not stop SwiftPM on
# Linux.  One file breaks it:
#
#   Sources/GrinderCore/HTTP/SHA256.swift
#     line 2:  import CryptoKit
#     line 11: Data(SHA256.hash(data: data))
#
# CryptoKit exists only on Apple platforms.  On Linux the equivalent is the
# `Crypto` module from the swift-crypto package, which Package.swift does not
# depend on, so `swift build` stops at "no such module 'CryptoKit'".  The
# `probe` stage below proves that claim without compiling anything and is
# expected to succeed; the `grindercore` stage is expected to fail.
#
# Neither stage was built in this session (no Android or iOS build was
# started), so the failure is derived from the source, not observed.
#
# Probe (expected to succeed):
#   docker build -f docker/ios-grindercore/Dockerfile --target probe \
#     --build-arg SWIFT_IMAGE=swift:6.3-noble@sha256:... -t e64-ios-probe .
# Reproducer (expected to fail at `swift build`):
#   docker build -f docker/ios-grindercore/Dockerfile --target grindercore \
#     --build-arg SWIFT_IMAGE=swift:6.3-noble@sha256:... .

ARG SWIFT_IMAGE
FROM ${SWIFT_IMAGE} AS probe

# Copy Sources and Tests by path instead of the package directory: the local
# tree also holds a macOS .build/ directory with Xcode intermediates, which has
# no business in a Linux image.
COPY apps/ios/GrinderCore/Package.swift /src/GrinderCore/Package.swift
COPY apps/ios/GrinderCore/Sources /src/GrinderCore/Sources
COPY apps/ios/GrinderCore/Tests /src/GrinderCore/Tests

WORKDIR /src/GrinderCore
RUN swift --version \
    && echo '-- unguarded Darwin-only imports (expected: only CryptoKit) --' \
    && grep -rn 'import CryptoKit\|import Security\|import UIKit' Sources \
    && echo '-- guarded Darwin-only imports --' \
    && grep -rn 'canImport(' Sources

FROM probe AS grindercore
RUN swift build -v
