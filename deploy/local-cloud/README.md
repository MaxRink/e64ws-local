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
| `api` | built from `deploy/local-cloud/Dockerfile` (**real service**), base `python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd` | the ten device-service routes, `/admin/v1/*`, `/healthz` | `internal` only |
| `proxy` | `caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0` | default edge: `Caddyfile.offline`, ports 8088 (http) + 8443 (`tls internal`), no certificate files | `edge` + `internal` |
| `proxy-device` | `caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0` | profile `device-tls`: the mTLS edge for the compiled hostname, ports 443/80; needs `certs/` + `pki/` | `edge-device` + `internal` |
| `db` | `postgres:18.7-alpine@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71` | in **`docker-compose.templates.yml`**, profile `postgres`: the design's target, **unused** — the service serves from SQLite | `internal` |
| `admin` | `caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0` | static owner console, loopback only | `admin` |

There is no `objects` row because there is no `objects` service: the MinIO
template was removed rather than left on a tag that cannot pull. See
[Object store](#object-store) for the evidence and for what re-adding one
takes.

Every pulled image above is pinned `tag@sha256:<index digest>` — the same
strings the Compose file carries, because this table is checked against it.
`tools/local_cloud/tests/deploy_pins_test.py` fails if a digest disappears, if a
service and a row disagree, or if a row outlives its service.

`internal` is a Docker network with no external route (`internal: true`), and
`api` is attached to it only: no published port, no outbound route. The admin
*API* is not a separate service — it lives on `api` behind
`LOCAL_CLOUD_ADMIN_TOKEN`, and neither Caddyfile routes `/admin/*`, so it is only
reachable from inside the `internal` network.

### The postgres template moved to a second Compose file

`db` is not in `docker-compose.yml` any more; it is in
[`docker-compose.templates.yml`](docker-compose.templates.yml), and **the
commands that touch it changed with it**:

```console
$ docker compose -f docker-compose.yml -f docker-compose.templates.yml \
    --profile postgres up -d --wait db        # works
$ docker compose --profile postgres up -d db
no such service: db
$ docker compose --profile postgres config --quiet   # silent no-op, exit 0
```

`--profile postgres` on its own now selects nothing and exits 0 without
printing anything, which is the trap: it is not an error, it just does not do
what it used to. Every template command below carries the two `-f` flags, and
the block that needs them sets `T` once instead of repeating them.

Why the split instead of a line in place: `docker compose config` interpolates
*every* service, including one in a profile that is not active. With
`POSTGRES_PASSWORD: "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}"` in
`docker-compose.yml`, a fresh checkout could not parse the default stack
(`api` + `proxy` + `admin`, none of which touches PostgreSQL) without a
database password. See "Credentials are required before the template starts".

`db` mounts `pgdata` at `/var/lib/postgresql`, not `/var/lib/postgresql/data`.
Since PostgreSQL 18 the image sets `PGDATA=/var/lib/postgresql/18/docker` and
declares `VOLUME /var/lib/postgresql`, so it wants the **parent** directory
mounted. See [Upgrading from 16](#upgrading-from-16) before pointing an existing
volume at the 18 image.

### PostgreSQL: 18.7 now, 19.0 not yet

`18.7` is the newest 18.x release — Docker Hub last published
`postgres:18.7-alpine` on 2026-11-21. There *is* a newer major:
`postgres:19.0-alpine` was published 2026-11-23, two days before these pins were
resolved. It is deliberately not adopted, and the reasons are the ones this
directory's own facts produce:

- `db` is a template that nothing writes to; there is no behaviour to gain, and
  19.0 has no point release yet.
- 19 moves `PGDATA` to `/var/lib/postgresql/19/docker` (verified:
  `docker run --rm --entrypoint /bin/sh postgres:19.0-alpine -c 'echo $PGDATA'`)
  while keeping `VOLUME /var/lib/postgresql`. The mount above is therefore still
  correct — but an 18 cluster becomes exactly as unreachable to 19 as a 16
  cluster is to 18, so moving majors is the same dump-and-restore in
  [Upgrading from 16](#upgrading-from-16), not a tag bump.

If you do move majors, change the tag here **and** rewrite that section and the
`db` comment in the Compose file in the same commit: the mount stays on the
parent, and Compose must not quietly reuse an 18 volume as if it were a 19 one.
Skipping that rewrite is how a documented migration path becomes a lie, so this
change pins 18.7 and leaves the 16 → 18 path intact instead.

**This pin is a floor, not a verdict.** 19 becomes the right move — and should
be taken then, not deferred again — as soon as all three of these hold: a 19.x
point release is out (so the pin is not on a `.0` with no fixes behind it),
something actually writes to `db` through the design's §4 wiring (today nothing
does, which is why the gain is zero), and the "Upgrading from 16" section has
been rewritten for 18 → 19 and re-run on a seeded volume the way the 16 → 18
path was. Move `postgres:19.x-alpine` and that section in the same commit.

## What you must create before it runs

1. **`.env`** — the documented file now exists as
   [`.env.example`](.env.example):

   ```sh
   cp .env.example .env
   chmod 600 .env
   ```

   Every credential in `.env.example` is **empty on purpose**, and the stack
   fails closed while they stay empty:

   * `LOCAL_CLOUD_ADMIN_TOKEN=` → the admin API answers
     `403 admin-not-configured` instead of opening. The file used to ship a
     ready-made token string, which is not a placeholder to the service — it is
     a token, and an anonymous `curl` presenting it got `400` (authorised) from
     `/admin/v1/*`.
   * `LOCAL_CLOUD_HOST=127.0.0.1` → right for a bare `python3 -m
     tools.local_cloud.service` on the host. Compose overrides the *container*
     bind to `0.0.0.0` on the `internal` network, which publishes nothing.
   * `LOCAL_CLOUD_TRUST_PROXY_IDENTITY` is commented out, so the default is
     `false`. Turn it on only behind an edge that **sets** the header from a
     real certificate (`Caddyfile`) and never behind one that has no
     certificate at all (`Caddyfile.offline`, which deletes the header).

   To enable the admin API:

   ```sh
   printf 'LOCAL_CLOUD_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)" >> .env
   ```

   `.env` is git-ignored. `.env.example` is *not* ignored (the repository root
   `.gitignore` excludes `.env.*`, and `deploy/local-cloud/.gitignore` re-includes
   the example) and contains no credential.

2. **Nothing else for the default stack.** `Caddyfile.offline` needs no
   certificates, so `caddy validate` passes on a fresh checkout (verified with
   `caddy:2.11.9-alpine`).

3. **For the device path (profile `device-tls`)** development material:

   ```sh
   sh gen-dev-certs.sh                     # prints "output directory: <mktemp -d path>"
   sh gen-dev-certs.sh ./certs-and-keys    # or an explicit directory of your own
   ```

   With no argument the script writes into a fresh `mktemp -d` under `umask 077`
   and prints the path at the end; it no longer defaults to this directory. (It
   used to: a CA **private key** landed in the working tree, where `.gitignore`
   is the only thing between it and a `git add -A`.) To use the generated
   material with the `device-tls` profile, either pass this directory as `$1` —
   `sh gen-dev-certs.sh .` reproduces the old behaviour deliberately — or copy
   `certs/` and `pki/` into this directory yourself.

   **Development only.** The real trust change is a planned, rollback-ready act
   on the owner's device (design §6/§7), not this script. The CA must be
   **EC P-256** (its PEM has to fit the 826-byte slot the patch replaces) and
   device client certificates must be **EC P-521** (the firmware rejects a
   P-256 certificate for the same key).

4. **DNS**: `ngx-secured.sync.mahlkoenig.com` must resolve to this host for the
   grinder only (design §6). Do not change public DNS.

## Edge binding: loopback by default, LAN is an opt-in

Both published listeners of `proxy` bind **127.0.0.1**:

```sh
docker compose config --format json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); \
      print([(p["host_ip"], p["published"]) for p in d["services"]["proxy"]["ports"]])'
# [('127.0.0.1', '8088'), ('127.0.0.1', '8443')]
```

`8088` used to be `"8088:8088"`, i.e. `0.0.0.0`: the offline edge answered every
host on the network segment, with no certificate and no identity, while the
`admin` service in the same file correctly pinned `127.0.0.1`. On a shared or
guest network that is a request path into the API for anyone on it.

For a device test from the LAN, opt in per command — do not edit the file:

```sh
LOCAL_CLOUD_EDGE_BIND=0.0.0.0 docker compose up -d proxy
```

The tradeoff, stated rather than implied: `LOCAL_CLOUD_EDGE_BIND=0.0.0.0`
publishes (a) plain HTTP on 8088, with no authentication of its own, and (b) a
`:8443` listener whose certificate comes from Caddy's internal CA, which no
client trusts without adding that CA first. Anything on the segment can reach
`/api/*` and be attributed however the API is configured to attribute it — fine
on a bench VLAN with a grinder, not fine on a laptop in a café.

**"No wildcard bind" is a statement about the default stack only.** Under the
`device-tls` profile, `proxy-device` still publishes `443` and `80` on every
interface, deliberately: the grinder has to reach that listener, and what
protects it is the TLS layer, not the bind address — every site in `Caddyfile`
requires a verified client certificate, and there is no site on `:443` without
one (see the invariant at the bottom of that file). `api` is never published
either way: it is on `internal`, which has no route out.

## Credentials are required before the template starts

`POSTGRES_PASSWORD` is interpolated with the Compose required-variable form, so
an unset or empty value stops `docker compose` before a container exists: the
`postgres` profile **refuses to start** rather than starting insecure. This
is the complete output — one line, because the only template left is `db` (the
`objects` half of this finding went away with the MinIO template in #57):

```console
$ cd deploy/local-cloud
$ docker compose -f docker-compose.yml -f docker-compose.templates.yml \
    --profile postgres config --quiet
error while interpolating services.db.environment.POSTGRES_PASSWORD: required
variable POSTGRES_PASSWORD is missing a value: set POSTGRES_PASSWORD in .env
$ echo $?
1
```

Set it in `.env` (or on the command line) and the same command exits 0. `db`
used to default to a placeholder string — a password PostgreSQL accepts — so
the profile started and stayed up with a published credential. The default
stack needs no credential, which is why `docker compose config --quiet` still
parses on a clean checkout:

```console
$ docker compose config --quiet
$ echo $?
0
```

## Memory, process and log limits

| Service | Limit | Why |
|---|---|---|
| all | `logging.options.max-size: 10m`, `max-file: 3` | the `json-file` driver grows without bound; both edges log one JSON line per request, so a home box fills `/var/lib/docker` in weeks. Rotation is the driver's own — no `logrotate`, no extra package. |
| `api` | `mem_limit: 256m` | stdlib Python + SQLite for ten routes. A leak or a pathological export hits the container, not the host's OOM killer. |
| `api` | `pids_limit: 200` | `ThreadingHTTPServer` spawns one thread per connection and threads are tasks in the cgroup, so this caps concurrent device requests plus the starter threads and turns a thread leak into a failing health check. The device polls one route every 5 s. |
| `admin` | `read_only: true` + `tmpfs: /tmp /config /data` | it serves a static directory and writes nothing; `/config` and `/data` are tmpfs because Caddy autosaves its JSON config on start-up and treats a write failure as non-fatal, so a tmpfs keeps the rootfs immutable without depending on that. |

What was deliberately **not** done, and why:

* **`read_only` on `proxy`/`proxy-device`.** Caddy writes certificates and ACME
  state into the `/data` and `/config` volumes by design; they are already the
  only writable paths that matter, and a read-only rootfs there adds a way for
  the edge to fail its health check without removing any writable state an
  attacker would use.
* **`read_only` on `api`.** It would probably work (`PYTHONDONTWRITEBYTECODE=1`
  is set in the image and SQLite stays inside `/var/lib/local-cloud`), but
  "probably" is not a claim worth making in a security fix that cannot start the
  stack in CI. Stated as a gap, not as a fix.
* **`cap_drop: [ALL]` on the Caddy services.** Caddy binds `:80`/`:443` inside
  its own namespace, so `ALL` plus no `cap_add` removes `NET_BIND_SERVICE` and
  the listener fails on start-up. The correct form is `cap_drop: [ALL]` plus
  `cap_add: [NET_BIND_SERVICE]` for `proxy-device` (and a plain `cap_drop` for
  `admin`, which binds 8080). Worth doing, but it changes what each container
  can do at start-up and cannot be verified from a `docker compose config`
  check, so it is named here rather than added unverified.
* **The Caddy containers run as root.** Lifting `user:` is not a one-line
  change: `/data` and `/config` are root-owned volumes, and `proxy-device` binds
  the privileged ports above. Doing it properly means chowning the volumes in
  the image and documenting it. Naming it beats half-doing it.
* **`no-new-privileges`.** Every process here is one that does not execve into
  anything after start-up: `api` runs as UID 10001 with no setuid binary in the
  image, and the `caddy` binary it runs is the one it started with. There is no
  privilege-escalation path in these images for `no-new-privileges` to block, so
  adding it would buy a flag, not a boundary — and a reviewer who reads "we set
  no-new-privileges" tends to stop looking. It is a deliberate non-fix, not an
  oversight: if any image here ever gains a helper binary, add it then.

## Bring up / tear down

```sh
docker compose config --quiet          # parse and interpolate, start nothing
docker compose build api               # build the service image
docker compose up -d                   # api + proxy + admin
docker compose --profile device-tls up -d proxy-device   # needs certs/pki
docker compose ps
docker compose logs -f api
docker compose down                    # keeps volumes
docker compose down -v                 # destroys state - lab only

# the postgres template lives in a second file: it needs the `-f` flags
T="-f docker-compose.yml -f docker-compose.templates.yml"
POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
  docker compose $T --profile postgres up -d --wait db   # template, unused
```

`--wait` makes the `db` step block on its `pg_isready` healthcheck instead of
racing the entrypoint; it is what the migration block below uses. **`db` needs
the two `-f` flags** (see [The postgres template moved](#the-postgres-template-moved-to-a-second-compose-file)):
`--profile postgres` without them selects nothing at all and exits 0, and
`--profile postgres up -d db` fails with `no such service: db`. There is no
`object-store` profile to pass — see [Object store](#object-store).

Smoke checks that need no device and no certificates. These **were** run, not
predicted: `docker compose up -d` (default profile), `--profile device-tls` with
`sh gen-dev-certs.sh` material, and `--profile postgres up -d --wait db`, on
Docker 29.8.2 / Compose v5.5.0 / arm64, 2026-11-25. Output is verbatim.

```console
$ docker compose ps --format 'table {{.Service}}\t{{.Status}}'
SERVICE        STATUS
admin          Up About a minute (healthy)
api            Up About a minute (healthy)
db             Up 8 seconds (healthy)
proxy          Up About a minute (healthy)
proxy-device   Up 45 seconds (healthy)

$ curl -s http://127.0.0.1:8088/ping
local-cloud offline edge

$ curl -s -o /dev/null -w '%{http_code}\n' \
    http://127.0.0.1:8088/api/device-service/system/time
401

$ curl -s http://127.0.0.1:8088/api/device-service/system/time
{"error":{"code":"unauthorized","message":"no client certificate presented and
anonymous access is off","reason":"client-certificate-required","status":401}}

$ curl -sk https://localhost:8443/ping          # Caddy's internal CA
local-cloud offline edge (tls)

$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/   # admin
200
```

The `device-tls` edge enforces mTLS at the handshake, so "no certificate" is a
TLS failure rather than a 401 body. It is keyed on the hostname compiled into
the firmware, so ask it with that name — `localhost` matches no site in
`Caddyfile` and Caddy answers 200 with an empty body, which is not a pass:

```console
$ H=ngx-secured.sync.mahlkoenig.com
$ curl -sk --resolve $H:443:127.0.0.1 -o /dev/null -w '%{http_code}\n' \
    https://$H/api/device-service/system/time
000            # curl exit 56: alert, no client certificate
$ curl -sk --resolve $H:443:127.0.0.1 \
    --cert certs/device-client.crt --key certs/device-client.key \
    -o /dev/null -w '%{http_code}\n' https://$H/api/device-service/system/time
401            # certificate accepted, device not enrolled yet
```

Enrol a device and see the 501 for `system/time`. The one-off container is on
the `internal` network, so it must address the service as `api`, **not**
`127.0.0.1` — inside that container `127.0.0.1` is the container itself, and an
earlier version of this block failed with `URLError [Errno 111] Connection
refused` for exactly that reason.

```sh
docker compose run --rm --no-deps --entrypoint python api -c '
import json, urllib.request
token = "the token from .env"
headers = {"Authorization": "Bearer " + token}
body = json.dumps({"deviceId": "dev-1", "certFingerprint": "AA" * 32}).encode()
urllib.request.urlopen(urllib.request.Request(
    "http://api:8080/admin/v1/devices", body, headers)).read()
request = urllib.request.Request(
    "http://api:8080/api/device-service/system/time",
    headers={"X-Client-Cert-Fingerprint": "AA" * 32})
try:
    urllib.request.urlopen(request)
except urllib.error.HTTPError as error:
    print(error.code, error.read().decode())
'
# verified 2026-11-25:
# 501 {"error":{"code":"unsupported","d_id":"D10",
#      "message":"D10.response.format: unknown — needs capture ...",
#      "reason":"timestamp-format-unknown","status":501,
#      "unverified_fields":["D10.response.format"]}}
```

`docker compose -f docker-compose.yml -f docker-compose.templates.yml
--profile postgres exec -T db sh -c 'echo $PGDATA; ls
/var/lib/postgresql; psql -U localcloud -d localcloud -tAc "select version()"'`
confirms the mount is the one this file describes (run on 2026-11-25, before
`db` moved into the templates file; the `-f` flags are the only change):

```console
PGDATA=/var/lib/postgresql/18/docker
18
PostgreSQL 18.7 on aarch64-unknown-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit
```

## Upgrading from 16

`db` used to be `postgres:16.4-alpine` with `pgdata` mounted at
`/var/lib/postgresql/data`. PostgreSQL 18 changed two things:

- `PGDATA` is now `/var/lib/postgresql/18/docker` — a major-version-specific
  directory — and
- the image declares `VOLUME /var/lib/postgresql`, so the mount belongs on the
  **parent**, not on `.../data`.

A volume written by 16 keeps the cluster at its **root**. Moving the mount does
not migrate anything, and 18 does not quietly start empty on it: the container
exits 1 and, because the service sets `restart: unless-stopped`, restart-loops
with

```
       Counter to that, there appears to be PostgreSQL data in:
         /var/lib/postgresql

       This is usually the result of upgrading the Docker image without
       upgrading the underlying database using "pg_upgrade" ...
```

That refusal destroys nothing — the 16 cluster is still intact and the 16 image
still serves it. The data is not lost, it is just unreachable by 18 until you
migrate it. Doing the migration is on you: bumping the tag and the mount in the
compose file cannot do it for you.

### If the volume holds data: dump and restore

In-place `pg_upgrade` is not an option here: the 18 image ships only the 18
server binaries, so it cannot run the 16 binaries `pg_upgrade` requires. Dump
with the 16 image while it can still read the old volume, then restore into a
fresh 18 volume.

Steps 1–2 are **non-destructive**. Step 3 deletes the source volume and is
refused unless step 2 printed `dump OK`. Every step gates on a real readiness or
content check, so a failure stops the block instead of costing you the data.

```sh
cd deploy/local-cloud

# The postgres template lives in a second Compose file (see "The postgres
# template moved"); every `docker compose --profile postgres` command below
# needs it. Without the -f flags the profile selects nothing and exits 0, which
# is a silent no-op rather than an error - do not drop $T.
T="-f docker-compose.yml -f docker-compose.templates.yml"

# 1. Dump from the OLD image on the OLD mount. Do not pass -v: keep the volume.
#    Gate on the server answering a query, with a bounded poll. Do NOT wait for
#    the log line "PostgreSQL init process complete": the entrypoint only prints
#    that when it runs initdb, so on a POPULATED volume - the case here - it
#    never appears (the log says "Skipping initialization" instead) and a dump
#    started too early dies with
#      FATAL:  the database system is not yet accepting connections
#    after writing a 0-byte file.
docker rm -f pg16-dump >/dev/null 2>&1 || true   # keep the step re-runnable
docker run -d --name pg16-dump \
  -e POSTGRES_PASSWORD=unused-this-process-only \
  -v local-cloud_pgdata:/var/lib/postgresql/data \
  postgres:16.4-alpine

for i in $(seq 1 60); do
  docker exec pg16-dump psql -U localcloud -d localcloud -tAc 'select 1' >/dev/null 2>&1 && break
  sleep 1
done
docker exec pg16-dump psql -U localcloud -d localcloud -tAc 'select 1' >/dev/null ||
  { echo "16.x never became ready - STOP, the volume is untouched"; exit 1; }

docker exec pg16-dump pg_dumpall -U localcloud > pg16-dumpall.sql ||
  { echo "pg_dumpall failed - STOP, the volume is untouched"; exit 1; }
docker rm -f pg16-dump >/dev/null

# 2. Prove the dump is usable BEFORE destroying anything. At this point nothing
#    has been deleted, so any failure here leaves the original volume intact.
test -s pg16-dumpall.sql ||
  { echo "dump is empty - STOP, the volume is untouched"; exit 1; }
grep -q 'PostgreSQL database cluster dump complete' pg16-dumpall.sql ||
  { echo "dump is truncated - STOP, the volume is untouched"; exit 1; }
DUMPED=$(awk '/^COPY .* FROM stdin;$/{f=1;next} /^\\\.$/{f=0;next} f{n++} END{print n+0}' pg16-dumpall.sql)
echo "dump OK: $(wc -c < pg16-dumpall.sql) bytes, $DUMPED data rows"

# 3. DESTRUCTIVE - and deliberately a step of its own. Only now may the source
#    go; from here the dump is the only copy. Want a second copy first? Clone
#    the volume with the image you already have, then keep going:
#      docker volume create local-cloud_pgdata_16_backup
#      docker run --rm -v local-cloud_pgdata:/from:ro \
#        -v local-cloud_pgdata_16_backup:/to \
#        postgres:16.4-alpine sh -c 'cp -a /from/. /to/'
docker compose $T --profile postgres down
docker volume rm local-cloud_pgdata

# 4. Fresh 18 volume. --wait blocks on the service healthcheck (pg_isready)
#    instead of racing the entrypoint's start-up.
docker compose $T --profile postgres up -d --wait db
docker compose $T --profile postgres exec -T db psql -U localcloud -d localcloud -tAc 'select 1' >/dev/null ||
  { echo "18.x not answering - STOP, pg16-dumpall.sql is intact, retry from step 4"; exit 1; }

# 5. Restore. `role` and `database` already exist because the entrypoint creates
#    them from POSTGRES_*, so these two errors are expected and harmless:
#      ERROR:  role "localcloud" already exists
#      ERROR:  database "localcloud" already exists
docker compose $T --profile postgres exec -T db \
  psql -U localcloud -d postgres -v ON_ERROR_STOP=0 < pg16-dumpall.sql

# 6. Verify by row count, not by eyeballing \l: dump the restored cluster and
#    compare the data rows each dump carries.
docker compose $T --profile postgres exec -T db pg_dumpall -U localcloud > pg18-dumpall.sql ||
  { echo "post-check dump failed - STOP, keep pg16-dumpall.sql"; exit 1; }
RESTORED=$(awk '/^COPY .* FROM stdin;$/{f=1;next} /^\\\.$/{f=0;next} f{n++} END{print n+0}' pg18-dumpall.sql)
echo "dumped: $DUMPED rows, restored: $RESTORED rows"
[ "$RESTORED" = "$DUMPED" ] ||
  { echo "MISMATCH - STOP, keep pg16-dumpall.sql and retry the restore"; exit 1; }

# 7. Only with the row counts equal may the plaintext dumps go.
rm -f pg16-dumpall.sql pg18-dumpall.sql
echo "migration verified: $RESTORED rows on 18.x, dumps removed"
```

Run against a seeded `postgres:16.4-alpine` volume → `postgres:18.7-alpine`
(Docker 29.8.2, Compose v5.5.0, arm64), three times from scratch: `dump OK: 4172
bytes, 2 data rows`, the two expected `already exists` errors, `dumped: 2 rows,
restored: 2 rows`, `migration verified: 2 rows on 18.x`, and both rows still
readable afterwards with `PG_VERSION` 18.

The 18.7 step now resolves through
`postgres:18.7-alpine@sha256:0115267a…` instead of the tag alone. The version and
the image content are the same 18.7 those transcripts came from — pinning added
a digest, it did not change the server — so the block above is unchanged and
still applies. Re-running it after any digest bump is the cheap way to keep this
paragraph true.

The block fails closed. Pointing the dump at a role that does not exist — the
easiest way to get an empty dump — stops at step 1 with `pg_dumpall failed -
STOP, the volume is untouched`; the source volume still had `PG_VERSION` 16 and
both rows afterwards, because step 3 is unreachable until the dump passes the
checks in step 2.

What this replaced, and why it mattered: the first version of this section said
"wait until the log says `PostgreSQL init process complete`" and then ran
`pg_dumpall`, `docker volume rm` and `rm pg16-dumpall.sql` with no check between
them. On a populated volume that log line never appears (the log says
`Skipping initialization`), so the dump raced the server and produced 0 bytes —
`FATAL: the database system is not yet accepting connections` — and the block
then deleted the source volume *and* the empty dump: silent, total loss of the
data it was supposed to migrate. Do not reinstate a log-line wait here.

### If the volume is empty: start fresh

Nothing in this stack writes to PostgreSQL yet — the service serves from SQLite
— so a `db` volume left over from experimenting is very likely worthless.

```sh
docker compose $T --profile postgres down -v
docker compose $T --profile postgres up -d db
```

`-v` deletes `pgdata`. Run the dump first if there is any chance the rows
matter; there is no undelete.

## Verify image pins

Every image above carries a tag **and** an index digest. The tag is for the
reader; the digest is what Docker actually resolves, so a retagged or
re-uploaded image cannot change what this stack runs.

| Reference | Tag published | Index digest (resolved 2026-11-25) |
|---|---|---|
| `python:3.15-alpine` | 2026-11-12 | `sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd` |
| `caddy:2.11.9-alpine` | 2026-11-13 | `sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0` |
| `postgres:18.7-alpine` | 2026-11-21 | `sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71` |

Each digest was resolved twice by different tools — `docker buildx imagetools
inspect <ref>` and `crane digest <ref>` — and the two agreed, which is what
rules out a digest copied from a per-platform manifest by mistake. All three are
multi-arch indexes (`application/vnd.oci.image.index.v1+json`) with a
`linux/arm64/v8` entry, so the same pin serves an x86 host and an Apple Silicon
laptop.

To re-check, or to bump:

```sh
# 1. What does the tag resolve to today?  Both must print the same digest.
docker buildx imagetools inspect caddy:2.11.9-alpine --format '{{json .Manifest}}' | head -c 120
crane digest caddy:2.11.9-alpine

# 2. Does the pinned reference still pull?  A digest that no longer resolves
#    fails here, not on the owner's laptop.
docker pull caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0

# 3. Then update the Compose file, this table and the Dockerfile FROM together.
PYTHONPATH=. python3 -m unittest tools.local_cloud.tests.deploy_pins_test
```

Those three `docker pull`s were run on 2026-11-25 and all resolved — verbatim,
each line naming the digest it resolved to:

```console
$ docker pull python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
Status: Downloaded newer image for python@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
docker.io/library/python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

$ docker pull caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
Status: Image is up to date for caddy@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
docker.io/library/caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0

$ docker pull postgres:18.7-alpine@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71
Status: Image is up to date for postgres@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71
docker.io/library/postgres:18.7-alpine@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71
```

`deploy_pins_test.py` then fails if a later edit drops a digest, switches to
`:latest`, or lets this table and the Compose file disagree. What it cannot do
offline is prove a digest is the *right* digest for its tag: a wrong digest
copied consistently into both files passes it. `docker pull` above is that
check, and it is the reason the transcripts are here rather than asserted.

### Python base: 3.15-alpine

The base moved from `python:3.12-alpine` to `python:3.15-alpine`, the newest
stable CPython minor that publishes an Alpine image (Docker Hub last pushed it
2026-11-12). 3.12 is still maintained but three minors behind. The service is
standard library only — no `requirements.txt`, no `pip install` in the
Dockerfile — so a base bump cannot break a dependency, only a module that a
minor removed. That is a claim worth evidence rather than confidence, so all
three checks were run on 2026-11-25:

```console
$ docker compose build api            # tail
#11 exporting to image
#11 writing image sha256:fe073856f71748370a9176fc6734d8c0b4f899f40c43b697ff1b602ea2530835 done
#11 naming to docker.io/library/local-cloud-service:dev done
 Image local-cloud-service:dev Built

$ docker run --rm --entrypoint python local-cloud-service:dev \
    -c 'import sys, platform; print(sys.version.split()[0], platform.libc_ver()[0] or "musl")'
3.15.2 musl

$ docker run -d --name lc-single local-cloud-service:dev
$ docker inspect -f '{{.State.Health.Status}}' lc-single
starting      # start_period
healthy       # afterwards; healthcheck log exit=0

$ PYTHONPATH=. python3 -m unittest discover -s tools/local_cloud/tests \
    -p "*_test.py" -t . -q
Ran 61 tests in 18.115s
OK (skipped=1)
```

Note the gap this leaves: `.github/workflows/tests.yml` runs the suite on
**3.11 and 3.13**, so CI does not execute on the interpreter this image ships.
The build, the image healthcheck and the 61-test run above are what cover it
here; adding `"3.15"` to that matrix is a one-line follow-up for whoever owns
the workflow.

## Object store

There is no `objects` service any more. The template named
`minio/minio:RELEASE.2024-08-17T01-24-54Z`, and that reference cannot be pulled
from anywhere — not "was not re-checked", as an earlier version of this file
said, but *gone*. What was found on 2026-11-25:

```text
$ docker pull minio/minio:RELEASE.2024-08-17T01-24-54Z
Error response from daemon: pull access denied for minio/minio, repository does
not exist or may require 'docker login': denied: requested access to the
resource is denied

$ curl -o /dev/null -w '%{http_code}' https://hub.docker.com/v2/repositories/minio/minio/
404
```

The `minio` namespace still exists on Docker Hub with 20 repositories in it —
`minio/mint`, `minio/operator`, `minio/warp` and so on — and the server image is
not among them. The mirrors are gone too: `quay.io/minio/minio` and
`ghcr.io/minio/minio` answer "no such manifest"/"manifest unknown",
`registry.min.io/minio/minio` does not resolve a manifest, and
`dl.min.io/server/minio/release/linux-amd64/minio.sha256sum` answers **HTTP 410
Gone**. MinIO's tagging scheme moved on: the current releases are published as
AIStor, where the tags are semver plus an `-edge` suffix
(`11.0.2-edge`, `edge-daily`) rather than the old `RELEASE.YYYY-MM-DDTHH-MM-SSZ`.

One MinIO-published server image does still resolve, and it was run rather than
assumed: `quay.io/minio/aistor/minio` (index digest
`sha256:107cf2014a9583c74c11e3cdbd6903d89c2244355886b89ce532f4ecae9c23f3`,
labels `release:RELEASE.2026-09-19T17-05-25Z`, `name:MinIO`). It is technically a
fine container — a bash shell, `curl 8.19.0`, a listener on `:9000` — and the
old healthcheck below would report it **healthy**:

```console
$ docker exec aistor-t curl -f -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9000/minio/health/live
200
```

That is exactly the problem, and it is a licensing one, not a packaging one.
AIStor is MinIO's commercial product; without a licence it starts, answers the
liveness probe, and refuses the work:

```console
WARN: No valid license found, running in offline mode. All S3 operations are denied.
      Please install a valid license using 'mc license update' to restore service.

$ docker exec aistor-t curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9000/
403
$ docker exec aistor-t curl -s http://127.0.0.1:9000/
<Error><Code>AccessDenied</Code><Message>Access denied. No license is installed.
Please install a valid license using &#39;mc license update&#39; to enable service.</Message>…
```

A container that is green while denying every S3 operation is worse than no
container: it would pass `docker compose ps`, pass a healthcheck, and fail the
first backup. Accepting a commercial licence is not a decision this skeleton
should make silently, and paying for one is not a version bump — so the service
is removed and the reason written down.

The choice was: leave a profile whose only image is unpullable, or remove it and
say why. Left in, `--profile object-store up` stays a documented command that
cannot work. Removed, nothing is lost that ever ran. Re-adding it is a short
change once you have picked an image and accepted its licence: pin it
`tag@sha256:<digest>`, restore the `objects` service and the `objectdata`
volume, add the README row — the `deploy_pins_test.py` table check will remind
you — and give the healthcheck an **authenticated S3 call**, not just
`/minio/health/live`, because the liveness probe above is 200 in exactly the
state you want the healthcheck to catch. The `S3_*` names stay in `.env.example`
for the design's §4 wiring; nothing reads them today.

## What this directory does not do

- No PostgreSQL, object store, notification or backup job is wired; `db` is a
  profile in `docker-compose.templates.yml` with nothing pointing at it, and
  there is no object store service at all (see [Object store](#object-store)).
- **No retention or rotation of the audit file.** `LOCAL_CLOUD_AUDIT_FILE` grows
  for as long as the stack runs: one JSON line per audited request, `write()` +
  `flush()` + `fsync()` each. Rotating it from inside the API is the one change
  that would create a way to drop rows, so it is left to whatever owns the
  volume (`logrotate` on a bind mount, or a supervisor that ships the file off
  the box). Not done here on purpose rather than half-done.
- **The audit file is not tamper-evident.** SQLite's `audit` table refuses
  `UPDATE` and `DELETE` through triggers; the JSONL mirror is written by the API
  process with `open(path, "a")`, so the same process could rewrite it. It is
  append-only by convention. Signing or shipping it off-host is the fix, and
  neither is implemented (design §8, "Audit").
- No rate limiting: Caddy core cannot express the per-certificate limits in
  design §8, and the service does not implement them.
- No firmware file server: D07 points `downloadUrl` at
  `LOCAL_CLOUD_ARTIFACT_BASE_URL` but nothing serves it.
- No secrets, keys or certificates in git. `.env`, `certs/`, `pki/` and `data/`
  are git-ignored, and `gen-dev-certs.sh` no longer defaults into the tree.
- The device-side trust change, DNS change and rollback live in design §6 and
  are not automated here.
