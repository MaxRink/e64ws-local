# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# Firmware-triage image: bsdtar, e2fsprogs, openssl, python3.
#
# Why: tools/firmware_triage.py needs exactly two external binaries - bsdtar to
# unpack the .swu cpio stream and openssl to verify sw-description.sig - and the
# workflow around it needs e2fsprogs to read the ext2/ext4 payload that
# tools/virtual-grinder/from_swu.sh extracts with debugfs.  A host missing one
# of them does not fail loudly: the tool degrades to "not observable", which
# reads like a clean result.  Pinning them is what makes the verdict mean
# something.
#
# Build:
#   docker build -f docker/firmware-triage/Dockerfile \
#     --build-arg DEBIAN_IMAGE=debian:bookworm-slim@sha256:... \
#     -t e64-firmware-triage docker
#
# Run (needs the repository mounted read-only; writes only under /tmp):
#   docker run --rm -v "$PWD:/repo:ro" -w /repo e64-firmware-triage \
#     sh docker/firmware-triage/smoke.sh

ARG DEBIAN_IMAGE
FROM ${DEBIAN_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# libarchive-tools is Debian's package for bsdtar.  cpio and gzip are what
# tools/vm-swu/make_test_swu.py needs to build a signed fixture locally, so the
# smoke test does not depend on having a vendor .swu or any network.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        libarchive-tools \
        e2fsprogs \
        openssl \
        cpio \
        gzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
CMD ["sh", "docker/firmware-triage/smoke.sh"]
