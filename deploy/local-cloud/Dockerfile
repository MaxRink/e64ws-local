# Local-cloud service image (skeleton).
#
# Build context is the repository root, because the service is the Python
# package tools/local_cloud and nothing here duplicates it:
#
#   docker build -f deploy/local-cloud/Dockerfile -t local-cloud-service:dev .
#
# Only the standard library is used at runtime - there is no requirements.txt
# and no pip install step on purpose.

# The tag is floating.  Pin it by digest before using this for anything real:
#   docker pull python:3.12-alpine
#   docker image inspect --format '{{index .RepoDigests 0}}' python:3.12-alpine
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOCAL_CLOUD_HOST=0.0.0.0 \
    LOCAL_CLOUD_PORT=8080 \
    LOCAL_CLOUD_DB=/var/lib/local-cloud/local-cloud.sqlite3 \
    LOCAL_CLOUD_AUDIT_FILE=/var/lib/local-cloud/audit.jsonl

WORKDIR /app

# adduser is BusyBox's on Alpine; -H keeps it without a home directory.
RUN adduser -D -H -u 10001 localcloud \
    && mkdir -p /var/lib/local-cloud \
    && chown -R localcloud:localcloud /var/lib/local-cloud

COPY tools/__init__.py /app/tools/__init__.py
COPY tools/local_cloud/ /app/tools/local_cloud/

USER localcloud

EXPOSE 8080

# Same check the Compose healthcheck runs; kept here so `docker run` alone is
# also self-checking.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]

ENTRYPOINT ["python", "-m", "tools.local_cloud.service"]
