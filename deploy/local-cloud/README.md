# local-cloud — deployment skeleton

**Status: runnable skeleton, not a deployment.** `api` builds and runs the
service in [`tools/local_cloud/service.py`](../../tools/local_cloud/service.py),
which serves the ten recorded device-service routes from SQLite. Every field
[`docs/LOCAL_CLOUD_DESIGN.md`](../../docs/LOCAL_CLOUD_DESIGN.md) marks
`unknown — needs capture` is refused with `501` and a reason token, so the
service is honest but **not device-ready**: a grinder configured against this
stack would get a 501 for `system/time`, `firmware/checkUpdate` and
`system/device-cert-download` until those captures exist.

Do not treat a green health check as a working local cloud. `/healthz` answers
`{"status":"ok"}` when the database is readable; it says nothing about the
device path being complete.

## Services

| Service | Image | Role | Network |
|---|---|---|---|
| `api` | built from `deploy/local-cloud/Dockerfile` (**real service**) | the ten device-service routes, `/admin/v1/*`, `/healthz` | `internal` only |
| `proxy` | `caddy:2.8.4-alpine` | default edge: `Caddyfile.offline`, ports 8088 (http) + 8443 (`tls internal`), no certificate files | `edge` + `internal` |
| `proxy-device` | `caddy:2.8.4-alpine` | profile `device-tls`: the mTLS edge for the compiled hostname, ports 443/80; needs `certs/` + `pki/` | `edge-device` + `internal` |
| `db` | `postgres:18.7-alpine` | profile `postgres`: the design's target, **unused** — the service serves from SQLite | `internal` |
| `objects` | `minio/minio:RELEASE.2024-08-17…` | profile `object-store`: template only, the tag does not pull | `internal` |
| `admin` | `caddy:2.8.4-alpine` | static owner console, loopback only | `admin` |

`internal` is a Docker network with no external route (`internal: true`), and
`api` is attached to it only: no published port, no outbound route. The admin
*API* is not a separate service — it lives on `api` behind
`LOCAL_CLOUD_ADMIN_TOKEN`, and neither Caddyfile routes `/admin/*`, so it is only
reachable from inside the `internal` network.

## What you must create before it runs

1. **`.env`** — the documented file now exists as
   [`.env.example`](.env.example):

   ```sh
   cp .env.example .env
   umask 077
   sed -i '' "s|^LOCAL_CLOUD_ADMIN_TOKEN=.*|LOCAL_CLOUD_ADMIN_TOKEN=$(openssl rand -hex 32)|" .env
   ```

   `.env` is git-ignored. `.env.example` is *not* ignored (the repository root
   `.gitignore` excludes `.env.*`, and `deploy/local-cloud/.gitignore` re-includes
   the example) and contains placeholders only, never a credential.

2. **Nothing else for the default stack.** `Caddyfile.offline` needs no
   certificates, so `caddy validate` passes on a fresh checkout (verified with
   `caddy:2.8.4-alpine`).

3. **For the device path (profile `device-tls`)** development material:

   ```sh
   sh gen-dev-certs.sh          # writes certs/ and pki/, prints the client fingerprint
   ```

   **Development only.** The real trust change is a planned, rollback-ready act
   on the owner's device (design §6/§7), not this script. The CA must be
   **EC P-256** (its PEM has to fit the 826-byte slot the patch replaces) and
   device client certificates must be **EC P-521** (the firmware rejects a
   P-256 certificate for the same key).

4. **DNS**: `ngx-secured.sync.mahlkoenig.com` must resolve to this host for the
   grinder only (design §6). Do not change public DNS.

## Bring up / tear down

```sh
docker compose config --quiet          # parse and interpolate, start nothing
docker compose build api               # build the service image
docker compose up -d                   # api + proxy + admin
docker compose --profile device-tls up -d proxy-device
docker compose ps
docker compose logs -f api
docker compose down                    # keeps volumes
docker compose down -v                 # destroys state - lab only
```

Smoke checks that need no device and no certificates. **Expected** output - the
stack was not started in the environment where this skeleton was written (see
`docs/LOCAL_CLOUD_DESIGN.md` "Implementation status"), so the three replies below
are predictions, not transcripts:

```sh
curl -s http://127.0.0.1:8088/ping
# expected: local-cloud offline edge

curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:8088/api/device-service/system/time
# expected: 401 - no client certificate, and ALLOW_ANONYMOUS is false

curl -sk https://localhost:8443/ping     # Caddy's internal CA
# expected: local-cloud offline edge (tls)
```

Enrol a device and see the 501 for `system/time` (the API is on the `internal`
network, so ask it from a container on that network). Same caveat: the status
and body shape are what the tests assert against the service directly; the
container hop itself is unverified here.

```sh
docker compose run --rm --no-deps --entrypoint python api -c '
import json, urllib.request
token = "the token from .env"
headers = {"Authorization": "Bearer " + token}
body = json.dumps({"deviceId": "dev-1", "certFingerprint": "AA" * 32}).encode()
urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:8080/admin/v1/devices", body, headers)).read()
request = urllib.request.Request(
    "http://127.0.0.1:8080/api/device-service/system/time",
    headers={"X-Client-Cert-Fingerprint": "AA" * 32})
try:
    urllib.request.urlopen(request)
except urllib.error.HTTPError as error:
    print(error.code, error.read().decode())
'
# 501 {"error": {"code": "unsupported", "d_id": "D10",
#       "reason": "timestamp-format-unknown", ... "unknown — needs capture" ...}}
```

## Verify image tags

Every tag above is a pin, but pins age. `caddy:2.8.4-alpine` and
`python:3.12-alpine` were pulled and used during this pass; the PostgreSQL and
MinIO tags were **not** re-checked here:

```sh
docker pull caddy:2.8.4-alpine python:3.12-alpine postgres:18.7-alpine
docker image inspect --format '{{index .RepoDigests 0}}' \
  caddy:2.8.4-alpine python:3.12-alpine postgres:18.7-alpine
```

## What this directory does not do

- No PostgreSQL, object store, notification, backup or retention job is wired;
  `db` and `objects` are profiles with nothing pointing at them.
- No rate limiting: Caddy core cannot express the per-certificate limits in
  design §8, and the service does not implement them.
- No firmware file server: D07 points `downloadUrl` at
  `LOCAL_CLOUD_ARTIFACT_BASE_URL` but nothing serves it.
- No secrets, keys or certificates in git. `.env`, `certs/`, `pki/` and `data/`
  are git-ignored.
- The device-side trust change, DNS change and rollback live in design §6 and
  are not automated here.
