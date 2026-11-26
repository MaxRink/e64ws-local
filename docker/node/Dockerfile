# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# Node 26 image for the decaid plugin suites.
#
# Why: decaid/ is a separate, gitignored checkout with its own Flutter
# toolchain, but four of its plugin suites are plain `node:test` scripts with no
# npm dependency at all (test/plugins/*.cjs).  They are the only part of decaid
# that can be reproduced without a Flutter SDK, so this image stops at the
# interpreter and mounts the checkout instead of baking it in - the checkout is
# not part of this repository and must not become part of an image.
#
# Build:
#   docker build -f docker/node/Dockerfile \
#     --build-arg NODE_IMAGE=node:26-slim@sha256:... -t e64-node:26 docker
#
# Run:
#   docker run --rm -v "$PWD/decaid:/decaid:ro" -w /decaid e64-node:26 \
#     sh -c 'node --test test/plugins/*.cjs'

ARG NODE_IMAGE
FROM ${NODE_IMAGE}

# node:* images already ship a uid-1000 `node` user, so nothing has to be
# created here: `node --test` reads the mounted checkout and writes its report
# to stdout.
USER node

WORKDIR /decaid
CMD ["sh", "-c", "node --test test/plugins/*.cjs"]
