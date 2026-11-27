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
| [`android/Dockerfile`](android/Dockerfile) | JDK 21 + SDK platform 37.2 + build-tools 36.0.0 + Gradle 9.9.2; the image builds, the app build is not run |
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
sh docker/verify.sh --only android --allow-skip   # a declared-only target
```

Exit status is 0 only when at least one target was built and proved.  A run whose
targets were all declared-only exits 1, because `passed 0, failed 0, skipped 1`
is not a green result; `--allow-skip` is the way to say the skip is the point.
The images run as an unprivileged user (see `python/Dockerfile`), so a mounted
tree has to be readable by uid 1000; `--clean` handles its own export.

`docker/dev-env/` is the older interactive development container. It is not one
of these targets, it is unchanged, and its base image is a tag rather than a
digest.
