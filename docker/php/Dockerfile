# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
# The base image is an ARG on purpose: docker/images.env is the only place
# a pin is written, so the FROM cannot drift away from it.
# PHP 8.4 module image: lint and exercise ondevice/*.php without a host PHP.
#
# Why: the owner-side module (ondevice/rest_api_dev.php and
# ondevice/e64local_action_run.php) only ever executes on the grinder, where the
# vendor ships PHP 8.4.16 under lighttpd and php-cgi (docs/PACKAGES.md).  A host
# PHP would be a different version with a different extension set, so checks
# made against it would describe the wrong machine.
#
# php:8.4-cli already contains both binaries and the SQLite extensions, so no
# PECL build and no network at run time.  Measured on the pinned digest:
#   php -v                      -> PHP 8.4.28 (cli)
#   command -v php-cgi          -> /usr/local/bin/php-cgi (cgi-fcgi)
#   php -m | grep -c sqlite     -> 2 (pdo_sqlite, sqlite3)
#
# Build:
#   docker build -f docker/php/Dockerfile \
#     --build-arg PHP_IMAGE=php:8.4-cli@sha256:... -t e64-php:8.4 docker
#
# Run one check:
#   docker run --rm -v "$PWD:/repo:ro" -w /repo e64-php:8.4 \
#     php -l ondevice/rest_api_dev.php

ARG PHP_IMAGE
FROM ${PHP_IMAGE}

# The sqlite3 command-line shell is for a human inspecting a /db copy.  The test
# suites stub it with a PHP script
# (tools/e64root/tests/fixtures/local_api/sqlite3_stub.php) and need only the
# extensions, which are already compiled in.
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Linting the module needs to read the mount and nothing else, so there is no
# reason to do it as root.
RUN useradd --create-home --uid 1000 --user-group php

ENV HOME=/home/php
USER php

WORKDIR /repo
CMD ["php", "-v"]
