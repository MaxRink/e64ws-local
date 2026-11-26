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

# g++ supplies the `c++` driver used by the two recon host tests.  There is no
# pip step on purpose: the suites are standard-library only, and a pip install
# would put a network dependency in front of a run that must stay offline.
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
CMD ["sh", "tools/run_tests.sh"]
