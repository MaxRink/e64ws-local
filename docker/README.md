# docker/ — reproducible build targets

One directory per buildable target, one pin file, one script that proves them.
The measurements, the commands and what is *not* proven live in
[`../docs/REPRODUCIBLE_BUILDS.md`](../docs/REPRODUCIBLE_BUILDS.md); this file is
only the map.

| Path | What it is |
|---|---|
| [`images.env`](images.env) | The only place a base-image digest is written |
| [`python/Dockerfile`](python/Dockerfile) | Python 3.11 / 3.13 / 3.15 tool suite, one image per interpreter |
| [`php/Dockerfile`](php/Dockerfile) | PHP 8.4 CLI + CGI + sqlite3 for the `ondevice/` module |
| [`firmware-triage/Dockerfile`](firmware-triage/Dockerfile) | `bsdtar`, `e2fsprogs`, `openssl`, `python3` |
| [`firmware-triage/smoke.sh`](firmware-triage/smoke.sh) | Builds a signed `.swu` fixture and triages it |
| [`node/Dockerfile`](node/Dockerfile) | Node 26 for the decaid plugin suites |
| [`android/Dockerfile`](android/Dockerfile) | JDK 21 + SDK 37 + Gradle 9.4.1, declaration only |
| [`ios-grindercore/Dockerfile`](ios-grindercore/Dockerfile) | Swift 6 on Linux, a reproducer that is expected to fail |
| [`compose.yaml`](compose.yaml) | The same targets for `docker compose`; the heavy two sit behind a profile |
| [`verify.sh`](verify.sh) | Builds every enabled target and asserts one command per target |
| [`selftest.py`](selftest.py) | Static checks on the pins, the compose file and this document |

## Run

```sh
sh docker/verify.sh --list        # what exists
sh docker/verify.sh --selftest    # pins and document, no docker calls
sh docker/verify.sh               # build + smoke the cheap targets
sh docker/verify.sh --all --clean # add the SKIP lines, mount a git-archive of HEAD
```

`docker/dev-env/` is the older interactive development container. It is not one
of these targets, it is unchanged, and its base image is a tag rather than a
digest.
