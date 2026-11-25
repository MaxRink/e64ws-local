# Offline device-service cloud

Replaces `https://ngx-secured.sync.mahlkoenig.com/api/device-service/` locally so
the grinder can run without the vendor cloud, and feeds it brew events from any
scale through a shot detector.

## Quick start

```sh
./gen_certs.sh /tmp/e64certs
./server.py --certs /tmp/e64certs --port 23455 --control-port 23090

# in another shell — no hardware required:
./bridge.py --simulate --control http://127.0.0.1:23090 --target 25

# as the grinder would:
curl -s --cacert /tmp/e64certs/ca.crt \
  -X POST -d '{"payload":{"grinderId":"HEM-HSG-HMI-S01"}}' \
  https://127.0.0.1:23455/api/device-service/brew-event/find
```

Verified output:

```json
{"brewEvents":[{"eventUuid":"4e3cc43c-…","deviceId":"HEM-HSG-HMI-S01",
 "brewer":{"scale":{"id":"local-scale"}},"groupNumber":"0",
 "doseIndex":"doubleShot","doseType":"doubleShot","validity":false,
 "duration":9600,"mass":18000,"grindEventUuid":"a35f1666-…",
 "stopTarget":0.0,"cloudDate":"2026-10-30T22:49:12Z"}],"count":1}
```

`validity:false` is correct for a 9.6 s shot — the gate requires >15 s.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/device-service/system/time` | timestamp |
| GET | `/api/device-service/firmware/checkUpdate` | always "no update" (no vendor OTA offline) |
| POST | `/api/device-service/brew-event/find` | returns and drains queued events for `grinderId` |
| GET | `/api/device-service/brewer-binding/find` | bindings |
| POST | `/api/device-service/device-event/fire` | records grinder→cloud events |
| GET | `/api/device-service/system/device-cert-download` | returns the local client cert |

Control API (`127.0.0.1:23090`): `POST /event`, `POST /bindings`, `GET /state`.

## TLS

`gen_certs.sh` creates a local CA, a server cert for
`ngx-secured.sync.mahlkoenig.com` (+ localhost/127.0.0.1 SANs) and a client cert.

- Server certificate verifies against `ca.crt` (tested 200).
- Client-certificate verification is **not enabled by default**: Python's
  `CERT_OPTIONAL`/`CERT_REQUIRED` broke the handshake in testing, so the default
  is `CERT_NONE` (server-auth only). `--require-client-cert` exists but is
  experimental.
- Whether the grinder verifies this server cert and what client certificate it
  presents is under test (`/tmp/ca-injection/`). If it verifies, install
  `ca.crt` as a trust anchor (rootfs bundle or `SSL_CERT_FILE` in `S90app`).

## Bridge

`bridge.py` reads HDS snapshots (`{"grams","ms"}`) or simulates them, detects a
stable final mass, applies the E64 validity window (>15 s, ≤ target+15 s) and
posts the event. Live mode:

```sh
./bridge.py --scale ws://hds.local/ --control http://127.0.0.1:23090
```

## Limits

- Gives **brew events only**, not grind control. Local grind control needs the
  dev-mode unlock (`docs/DEV_MODE_AND_LOCAL_CONTROL.md`).
- No vendor OTA: firmware updates stay signed-only.
- Bindings/recipes/stats endpoints are stubs with correct shapes, not full
  implementations.
