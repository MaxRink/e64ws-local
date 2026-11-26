# Local-cloud service image (skeleton).
#
# Build context is the repository root, because the service is the Python
# package tools/local_cloud and nothing here duplicates it:
#
#   docker build -f deploy/local-cloud/Dockerfile -t local-cloud-service:dev .
#
# Only the standard library is used at runtime - there is no requirements.txt
# and no pip install step on purpose.

# Pinned by digest, not just by tag.  `python:3.15-alpine` is the newest stable
# CPython minor with an Alpine image (3.12, the previous base, is still
# maintained but three minors behind; CI in .github/workflows/tests.yml covers
# 3.11 and 3.13, so 3.15 is additionally proven by building this image and
# running the local-cloud suite plus the image healthcheck - see README.md
# "Verify image pins").  The digest below is the multi-arch *index* digest:
#
#   docker buildx imagetools inspect python:3.15-alpine   -> sha256:0f9552bb...
#   crane digest python:3.15-alpine                       -> sha256:0f9552bb...
#
# Keep the tag for the reader and the digest for the resolver.  Bump both, or
# tools/local_cloud/tests/deploy_pins_test.py fails.
FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOCAL_CLOUD_HOST=0.0.0.0 \
    LOCAL_CLOUD_PORT=8080 \
    LOCAL_CLOUD_DB=/var/lib/local-cloud/local-cloud.sqlite3 \
    LOCAL_CLOUD_AUDIT_FILE=/var/lib/local-cloud/audit.jsonl

WORKDIR /app

# Take the base image's apk packages from the current repository rather than
# from whatever Alpine snapshot the base tag was built against.  The image
# scanner reports 16 HIGH findings against packages the service never touches
# (krb5-libs and friends) plus MEDIUM findings against libcrypto3/libssl3, which
# this service *does* reach - it terminates mutual TLS with them.
RUN apk upgrade --no-cache

# adduser is BusyBox's on Alpine; -H keeps it without a home directory.
RUN adduser -D -H -u 10001 localcloud \
    && mkdir -p /var/lib/local-cloud \
    && chown -R localcloud:localcloud /var/lib/local-cloud

# The runtime is the standard library only, so the interpreter's bundled
# packaging tools are never imported: they are dead weight that the scanner
# still reports on (five MEDIUM findings in pip).  The guard keeps the build
# working if a future base stops shipping pip at all.
#
# Uninstalling pip is not enough on its own: CPython also ships
# ``ensurepip/_bundled/pip-*.whl`` (~1.8 MB), which the scanner reports just the
# same and which ``python -m ensurepip`` would install straight back.  The path
# is discovered rather than hard-coded so a Python minor bump cannot silently
# leave the wheel behind.
RUN set -eux; \
    if python -m pip --version >/dev/null 2>&1; then \
        python -m pip uninstall -y pip setuptools wheel; \
    fi; \
    rm -rf "$(python -c 'import ensurepip, os; print(os.path.dirname(ensurepip.__file__))')"; \
    rm -rf /root/.cache/pip

# ``*.py`` and not the whole directory: tools/local_cloud/tests is the test
# suite, it is not imported at runtime, and copying it put the entire suite -
# and its fixtures - into the shipped image.
COPY tools/__init__.py /app/tools/__init__.py
COPY tools/local_cloud/*.py /app/tools/local_cloud/

USER localcloud

EXPOSE 8080

# Same check the Compose healthcheck runs; kept here so `docker run` alone is
# also self-checking.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]

ENTRYPOINT ["python", "-m", "tools.local_cloud.service"]
