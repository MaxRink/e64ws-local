# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# Python tool-suite image for the offline repository tests.
#
# Why: the suites import the standard library only, so almost nothing can drift
# except the interpreter itself and the host C++ compiler that the recon-cxx
# gate shells out to (`c++ -std=c++14` in
# tools/rebuild/esp-app/recon/tests/run_scale_gateway_test.sh).  Pinning the
# interpreter by digest and installing exactly one package reproduces the thing
# the tests actually depend on, and nothing else.
#
# Build (the pin lives in docker/images.env, so pass it in):
#   docker build -f docker/python/Dockerfile \
#     --build-arg PYTHON_IMAGE=python:3.13-slim@sha256:... \
#     -t e64-py:3.13 docker
#
# Run:
#   docker run --rm -v "$PWD:/repo:ro" -w /repo e64-py:3.13 sh tools/run_tests.sh

ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Three packages, each named for the test that needs it:
#
#   g++               the `c++` driver the two recon host tests invoke
#   libarchive-tools  bsdtar, which tools/firmware_triage.py shells out to.  The
#                     host happens to have /usr/bin/bsdtar, so this dependency is
#                     invisible until the suite runs in a container: without it
#                     the `tools` suite reports 11 failures and 3 errors in
#                     tools.test_firmware_triage (every package reads as
#                     "no-description"), and verify.sh fails the target.  openssl
#                     is already in the python image and is the tool's other
#                     external binary.
#   git               the binary itself, not a checkout: tools.test_public_export
#                     runs `git status --porcelain`, `git ls-files` and the like
#                     against the tree it is given, so on a host with git the
#                     suite passes and in this image it died with
#                     `FileNotFoundError: 'git'` (5 failures, 20 errors).
#
# There is no pip step on purpose: the suites import the standard library only,
# and a pip install would put a network dependency in front of a run that must
# stay offline.
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ libarchive-tools git \
    && rm -rf /var/lib/apt/lists/*

# Run the suites unprivileged.  They write only under TMPDIR (/tmp, mode 1777)
# and read the mounted repository, so nothing here needs root - and a test run
# that can write to the whole filesystem is a worse default than one that
# cannot.  uid 1000 is the first regular uid on Debian and the usual desktop
# uid, which keeps owned-by-me files visible on the host.
#
# Consequence, stated because it surprises people: the mounted tree must be
# readable by uid 1000.  verify.sh --clean makes its git-archive export
# world-readable for exactly this reason, and prints a NOTE when a work-tree run
# sees a file that is not.
RUN useradd --create-home --uid 1000 --user-group tester

ENV HOME=/home/tester
USER tester

WORKDIR /repo
CMD ["sh", "tools/run_tests.sh"]
