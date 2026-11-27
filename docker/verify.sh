#!/bin/sh
# Build every enabled target under docker/ and run one command that proves it.
#
# Why: docs/REPRODUCIBLE_BUILDS.md claims that a target builds.  A claim whose
# command cannot fail is a guess, so every target here is `docker build` plus a
# smoke command whose output is asserted, and the exit status aggregates all of
# them.  The two targets that must not be built here (Android, Swift-on-Linux)
# are declared and skipped with a reason instead of being quietly absent.
#
# Usage:
#   sh docker/verify.sh                 # the cheap, local targets
#   sh docker/verify.sh --all           # same, plus the SKIP lines for the heavy ones
#   sh docker/verify.sh --only py313    # one target
#   sh docker/verify.sh --clean         # mount a pristine export of HEAD, not the work tree
#   sh docker/verify.sh --list          # what exists, without building
#   sh docker/verify.sh --selftest      # scaffold invariants only, no docker calls
#   sh docker/verify.sh --only android --allow-skip  # a declared-only target, deliberately
# Exit status is 0 only when at least one target was built and proved.  A run
# that skipped every target exits 1 unless --allow-skip says the skip is the
# point, because "passed 0, failed 0, skipped 1" is not a green run: nothing was
# built, so nothing was verified.
#
# --clean exists because "the image works" must not depend on somebody else's
# uncommitted file: the suite's coverage manifest fails on any test_*.py that is
# not registered, so a half-finished file in the work tree turns the image red
# for a reason the image did not cause.  --clean exports HEAD with git archive
# and mounts that for the Python and PHP smokes; the firmware and decaid smokes
# keep reading the work tree, because the triage CLI and the decaid checkout are
# working-tree artifacts that a HEAD export does not contain.
#
# Requirements: docker with buildx (Docker 29 and Compose v5 were used), network
# access for the base images, and the repository checkout itself.  Nothing is
# written outside the docker image store and /tmp.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/.." && pwd)

if [ ! -f "$HERE/images.env" ]; then
    printf 'verify: missing %s\n' "$HERE/images.env" >&2
    exit 2
fi
# shellcheck disable=SC1091
. "$HERE/images.env"

# Targets that are cheap enough to build and run here, and the two that are not.
DEFAULT_TARGETS='py311 py313 py315 firmware-triage php node26'
HEAVY_TARGETS='android ios-grindercore'
ALL_TARGETS="$DEFAULT_TARGETS $HEAVY_TARGETS"

# The one suite allowed not to report, and why: see smoke_python.
KNOWN_HANG='recon-cxx'
# Bounded so a hang cannot hold the whole run.  SUITE_TIMEOUT=0 disables the
# bound and is only useful when debugging the hang itself.
SUITE_TIMEOUT=${SUITE_TIMEOUT:-600}

usage() {
    # Print from the `# Usage:` heading to the next paragraph break, so a line
    # added above or below cannot silently truncate --help.
    sed -n '/^# Usage:/,/^#$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

target_image() {
    case $1 in
        py311) printf 'e64-py:3.11\n' ;;
        py313) printf 'e64-py:3.13\n' ;;
        py315) printf 'e64-py:3.15\n' ;;
        firmware-triage) printf 'e64-firmware-triage:latest\n' ;;
        php) printf 'e64-php:8.4\n' ;;
        node26) printf 'e64-node:26\n' ;;
        android) printf 'e64-android:latest\n' ;;
        ios-grindercore) printf 'e64-ios-grindercore:probe\n' ;;
        *) return 1 ;;
    esac
}

build_target() {
    target=$1
    image=$(target_image "$target")
    case $target in
        py311 | py313 | py315)
            # One explicit arm per interpreter, so the pin passed to the build
            # can be read straight out of docker/images.env by eye and by the
            # selftest, without a lookup function in the way.
            pin=$PYTHON_311
            case $target in
                py313) pin=$PYTHON_313 ;;
                py315) pin=$PYTHON_315 ;;
            esac
            docker build -f "$HERE/python/Dockerfile" \
                --build-arg "PYTHON_IMAGE=$pin" \
                -t "$image" "$HERE"
            ;;
        firmware-triage)
            docker build -f "$HERE/firmware-triage/Dockerfile" \
                --build-arg "DEBIAN_IMAGE=$DEBIAN_BOOKWORM" \
                -t "$image" "$HERE"
            ;;
        php)
            docker build -f "$HERE/php/Dockerfile" \
                --build-arg "PHP_IMAGE=$PHP_84" \
                -t "$image" "$HERE"
            ;;
        node26)
            docker build -f "$HERE/node/Dockerfile" \
                --build-arg "NODE_IMAGE=$NODE_26" \
                -t "$image" "$HERE"
            ;;
        *)
            printf 'verify: no build rule for %s\n' "$target" >&2
            return 1
            ;;
    esac
}

# -- assertions ------------------------------------------------------------
# Each smoke prints the interesting tail of the real output and then asserts on
# it, so a green line means the command ran and said the expected thing.

assert_contains() {
    haystack=$1
    needle=$2
    label=$3
    if ! printf '%s\n' "$haystack" | grep -qF -- "$needle"; then
        printf 'verify: %s: output does not contain %s\n' "$label" "$needle" >&2
        return 1
    fi
}

# The suite order tools/run_tests.py will use, as printed by the runner itself.
# Only consulted when a run is bounded, so it costs nothing on a green run.
runner_suite_order() {
    docker run --rm -v "$SOURCE:/repo:ro" -w /repo/tools "$1" \
        python -c 'import run_tests; print(" ".join(suite.name for suite in run_tests.SUITES))' \
        2>/dev/null
}

# A bounded run (exit 124) is the known hang exactly when the runner's last suite
# is KNOWN_HANG and every earlier suite reported.  tools/run_tests.py prints a
# suite's `== name ==` header only after that suite has finished, so the hanging
# suite is precisely the one whose header never appears: checking the last
# *visible* header against KNOWN_HANG could never succeed, which is why this
# compares the reported count against the runner's own order instead of trusting
# a hand-maintained list.
bounded_run_is_the_known_hang() {
    # Names are prefixed because POSIX sh has no `local`, and smoke_python
    # carries `image`/`passes` in the same globals.
    _image=$1
    _reported=$2
    _order=$(runner_suite_order "$_image") || return 1
    [ -n "$_order" ] || return 1
    # shellcheck disable=SC2086
    set -- $_order
    _total=$#
    _last=$1
    for _name in "$@"; do
        _last=$_name
    done
    [ "$_last" = "$KNOWN_HANG" ] || return 1
    # Every suite except the one that hung must have reported a header.
    [ "$_reported" -eq $(( _total - 1 )) ]
}

python_version() {
    case $1 in
        py311) printf '3.11\n' ;;
        py313) printf '3.13\n' ;;
        py315) printf '3.15\n' ;;
        *) return 1 ;;
    esac
}

smoke_python() {
    target=$1
    version=$(python_version "$target")
    image=$(target_image "$target")
    status=0
    output=$(docker run --rm -v "$SOURCE:/repo" -w /repo "$image" \
        sh -c "python -VV; timeout ${SUITE_TIMEOUT} sh tools/run_tests.sh") || status=$?
    printf '%s\n' "$output" | grep -E '^== |^  (PASS|FAIL|ERROR):|^Result: ' | tail -n 12

    # Two suites cannot be green inside a plain container, and both reasons are
    # properties of the repository's runner rather than of this image:
    #
    #   e64root     the 35 container tests in PhpModuleCase and
    #               RunnerJobValidationTests need a docker CLI and a local
    #               php:8.3-cli image (tools/run_tests.py declares it in
    #               docker_images and probes it before discovery), so inside a
    #               container the suite reports ERROR with
    #               "php:8.3-cli is not available; docker pull php:8.3-cli" or
    #               "docker is not installed; ..." instead of running.
    #   recon-cxx   the host gateway binary compiles and then does not terminate
    #               in any Linux container tested (Debian 12 g++ 12.2/glibc 2.36
    #               and Debian 13 g++ 14.2/glibc 2.41), while it completes on the
    #               macOS host.  It is the last suite, so the bounded run ends
    #               there with exit 124.
    #
    # Both names are listed explicitly: any other suite failing, or any suite
    # disappearing, still fails this target.
    KNOWN_FAILING='e64root'
    KNOWN_HANG='recon-cxx'

    headers=$(printf '%s\n' "$output" | grep -c '^== ' || true)
    passes=$(printf '%s\n' "$output" | grep -c '^  PASS:' || true)
    last_suite=$(printf '%s\n' "$output" | grep '^== ' | tail -n 1 | sed 's/^== //; s/ ==$//')

    assert_contains "$output" "Python $version." "$target" || return 1

    # Pair every suite header with the status line that follows it.
    unexpected=$(printf '%s\n' "$output" |
        awk '/^== /{suite=$2} /^  (FAIL|ERROR):/{print suite}' |
        grep -vxF "$KNOWN_FAILING" || true)
    if [ -n "$unexpected" ]; then
        printf 'verify: %s: unexpected failing suite(s): %s\n' "$target" "$unexpected" >&2
        return 1
    fi
    if [ "$status" -eq 0 ]; then
        assert_contains "$output" 'Result: PASS' "$target" || return 1
    elif [ "$status" -eq 124 ] && bounded_run_is_the_known_hang "$image" "$headers"; then
        printf '    WARN %s: the run stopped in %s, the known Linux hang; %s earlier suites passed\n' \
            "$target" "$KNOWN_HANG" "$passes"
    else
        printf 'verify: %s: suite command exited %s in suite %s (%s headers, %s passes)\n' \
            "$target" "$status" "$last_suite" "$headers" "$passes" >&2
        return 1
    fi
    # Sum the "ran N" of every suite that reported, so a silent drop of whole
    # suites cannot pass as a short green run.
    ran=$(printf '%s\n' "$output" | sed -n 's/^  PASS: ran \([0-9][0-9]*\),.*/\1/p' |
        awk '{ total += $1 } END { print total + 0 }')
    if [ "$ran" -lt 300 ]; then
        printf 'verify: %s: only %s tests ran across %s passing suites\n' "$target" "$ran" "$passes" >&2
        return 1
    fi
    printf '    python %s: %s suites passed, %s tests, 1 known-incomplete suite (%s)\n' \
        "$version" "$passes" "$ran" "$KNOWN_HANG"
}

smoke_firmware_triage() {
    image=$(target_image firmware-triage)
    output=$(docker run --rm -v "$REPO:/repo:ro" -w /repo "$image" \
        sh docker/firmware-triage/smoke.sh) || {
        printf 'verify: firmware-triage: the smoke script failed\n' >&2
        return 1
    }
    printf '%s\n' "$output"
    assert_contains "$output" 'SMOKE OK: mke2fs + debugfs round-tripped a file through ext4' firmware-triage || return 1
    assert_contains "$output" 'SMOKE OK: firmware-triage image is usable' firmware-triage || return 1
}

smoke_php() {
    image=$(target_image php)
    output=$(docker run --rm -v "$SOURCE:/repo:ro" -w /repo "$image" sh -c '
        php -v | head -1
        php-cgi -v | head -1
        printf "sqlite extensions: %s\n" "$(php -m | grep -ci sqlite)"
        php -l ondevice/rest_api_dev.php
        php -l ondevice/e64local_action_run.php
    ') || {
        printf 'verify: php: the lint command failed\n' >&2
        return 1
    }
    printf '%s\n' "$output"
    assert_contains "$output" 'PHP 8.4.' php || return 1
    assert_contains "$output" 'cgi-fcgi' php || return 1
    assert_contains "$output" 'sqlite extensions: 2' php || return 1
    assert_contains "$output" 'No syntax errors detected in ondevice/rest_api_dev.php' php || return 1
    assert_contains "$output" 'No syntax errors detected in ondevice/e64local_action_run.php' php || return 1
}

smoke_node26() {
    image=$(target_image node26)
    if [ ! -d "$REPO/decaid" ]; then
        printf '    SKIP node26 suites: %s/decaid is absent\n' "$REPO"
        printf '    (decaid is a separate gitignored checkout; the image still built)\n'
        output=$(docker run --rm "$image" node --version) || return 1
        printf '    node in image: %s\n' "$output"
        return 0
    fi
    output=$(docker run --rm -v "$REPO/decaid:/decaid:ro" -w /decaid "$image" \
        sh -c 'node --test test/plugins/*.cjs') || {
        printf 'verify: node26: the plugin suites failed\n' >&2
        return 1
    }
    printf '%s\n' "$output" | tail -n 10
    if printf '%s\n' "$output" | grep -q '^not ok'; then
        printf 'verify: node26: at least one node:test case failed\n' >&2
        return 1
    fi
    assert_contains "$output" 'fail 0' node26 || return 1
    if ! printf '%s\n' "$output" | grep -qE 'pass [1-9][0-9]*$'; then
        printf 'verify: node26: no passing tests were reported\n' >&2
        return 1
    fi
}

smoke_target() {
    case $1 in
        py311 | py313 | py315) smoke_python "$1" ;;
        firmware-triage) smoke_firmware_triage ;;
        php) smoke_php ;;
        node26) smoke_node26 ;;
        *)
            printf 'verify: no smoke rule for %s\n' "$1" >&2
            return 1
            ;;
    esac
}

# -- driver ----------------------------------------------------------------

run_target() {
    target=$1
    image=$(target_image "$target")
    printf '\n== %s -> %s ==\n' "$target" "$image"
    started=$(date +%s)
    if ! build_target "$target"; then
        printf 'RESULT %s FAIL (build)\n' "$target"
        printf '%s %s FAIL build\n' "$target" "$image" >>"$SUMMARY"
        FAILED=$((FAILED + 1))
        return 0
    fi
    built=$(date +%s)
    if ! smoke_target "$target"; then
        printf 'RESULT %s FAIL (smoke)\n' "$target"
        printf '%s %s FAIL smoke\n' "$target" "$image" >>"$SUMMARY"
        FAILED=$((FAILED + 1))
        return 0
    fi
    finished=$(date +%s)
    printf 'RESULT %s PASS (build %ss, smoke %ss)\n' \
        "$target" "$((built - started))" "$((finished - built))"
    printf '%s %s PASS build=%ss smoke=%ss\n' \
        "$target" "$image" "$((built - started))" "$((finished - built))" >>"$SUMMARY"
    PASSED=$((PASSED + 1))
    return 0
}

skip_target() {
    target=$1
    case $target in
        android)
            printf '\n== %s -> %s ==\n' "$target" "$(target_image "$target")"
            printf 'SKIP android: not built by this script, because the layer set needs\n'
            printf '     the Android SDK behind a licence prompt.  The image was built\n'
            printf '     and verified separately on 2026-11-26 -- all six layers, running\n'
            printf '     as uid=1000(ubuntu); docs/REPRODUCIBLE_BUILDS.md section 6.\n'
            printf '     Still unverified there: the Gradle/Maven build the CMD runs, and\n'
            printf '     the commandline-tools SHA-256 (CMDLINE_TOOLS_SHA256 is unset).\n'
            printf '     See docker/android/Dockerfile and docs/REPRODUCIBLE_BUILDS.md.\n'
            ;;
        ios-grindercore)
            printf '\n== %s -> %s ==\n' "$target" "$(target_image "$target")"
            printf 'SKIP ios-grindercore: repo-side expectation is a failure, not a build.\n'
            printf '     Sources/GrinderCore/HTTP/SHA256.swift imports CryptoKit, which\n'
            printf '     does not exist on Linux; the package cannot build there.\n'
            printf '     See docker/ios-grindercore/Dockerfile for the reproducer.\n'
            ;;
        *)
            printf 'SKIP %s: no reason recorded\n' "$target"
            ;;
    esac
    printf '%s %s SKIP declared-only\n' "$target" "$(target_image "$target")" >>"$SUMMARY"
    SKIPPED=$((SKIPPED + 1))
}

mode=default
only=
clean=0
allow_skip=0
while [ $# -gt 0 ]; do
    case $1 in
        --all) mode=all ;;
        --allow-skip) allow_skip=1 ;;
        --only)
            [ $# -ge 2 ] || { printf 'verify: --only needs a target\n' >&2; exit 2; }
            only=$2
            shift
            ;;
        --clean) clean=1 ;;
        --list) mode=list ;;
        --selftest) mode=selftest ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'verify: unknown argument %s (try --help)\n' "$1" >&2
            exit 2
            ;;
    esac
    shift
done

case $mode in
    list)
        printf '%-16s %-26s %s\n' target image kind
        for t in $ALL_TARGETS; do
            kind=enabled
            case " $HEAVY_TARGETS " in
                *" $t "*) kind=declared-and-skipped ;;
            esac
            printf '%-16s %-26s %s\n' "$t" "$(target_image "$t")" "$kind"
        done
        exit 0
        ;;
    selftest)
        exec python3 "$HERE/selftest.py" -v
        ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    printf 'verify: docker is not on PATH\n' >&2
    exit 2
fi

if [ -n "$only" ]; then
    case " $ALL_TARGETS " in
        *" $only "*) : ;;
        *)
            printf 'verify: unknown target %s (see --list)\n' "$only" >&2
            exit 2
            ;;
    esac
    targets=$only
elif [ "$mode" = all ]; then
    targets=$ALL_TARGETS
else
    targets=$DEFAULT_TARGETS
fi

SUMMARY=$(mktemp "${TMPDIR:-/tmp}/verify-summary.XXXXXX")
CLEAN_TREE=
trap 'rm -f "$SUMMARY"; [ -n "$CLEAN_TREE" ] && rm -rf "$CLEAN_TREE"' EXIT INT TERM
PASSED=0
FAILED=0
SKIPPED=0

# What the Python and PHP smokes read.  The default is the work tree, because
# that is what a developer wants to test; --clean swaps in a git-archive export
# of HEAD so the result cannot be coloured by uncommitted work.
SOURCE=$REPO
if [ "$clean" = 1 ]; then
    if ! command -v git >/dev/null 2>&1; then
        printf 'verify: --clean needs git on PATH\n' >&2
        exit 2
    fi
    CLEAN_TREE=$(mktemp -d "${TMPDIR:-/tmp}/e64-head.XXXXXX")
    if ! git -C "$REPO" archive --format=tar HEAD | tar -x -C "$CLEAN_TREE"; then
        printf 'verify: could not export HEAD with git archive\n' >&2
        exit 2
    fi
    if [ ! -f "$CLEAN_TREE/tools/run_tests.py" ]; then
        printf 'verify: the HEAD export in %s looks empty\n' "$CLEAN_TREE" >&2
        exit 2
    fi
    # `git archive` writes no repository metadata, and the suites now include
    # tests that run git against the checkout they are given (tools.test_public_export
    # calls `git status --porcelain` and refuses a --repo that is not a repository),
    # so a bare export fails them for a reason that has nothing to do with the image.
    # Give the export a throwaway repository of its own: the *content* is still
    # exactly HEAD, which is the property --clean exists to provide.
    if ! git -C "$CLEAN_TREE" init -q \
        || ! git -C "$CLEAN_TREE" add -A \
        || ! git -C "$CLEAN_TREE" -c user.name=verify -c user.email=verify@localhost \
            commit -q -m 'git archive HEAD'; then
        printf 'verify: could not give the HEAD export a throwaway repository\n' >&2
        exit 2
    fi
    # The images run as uid 1000 (see docker/python/Dockerfile), and mktemp -d
    # creates a 0700 directory owned by whoever ran this script, so the export has
    # to be opened up or every container would fail to read /repo.
    chmod -R a+rX "$CLEAN_TREE"
    SOURCE=$CLEAN_TREE
elif command -v git >/dev/null 2>&1; then
    if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]; then
        printf 'verify: NOTE the work tree has uncommitted changes, so the Python\n'
        printf '        suite result describes them too.  Use --clean to test HEAD.\n'
    fi
fi

# The images do not run as root, so a file the container's uid 1000 cannot read
# fails the run for a reason the image did not cause.  Say so instead of letting
# it surface as a permission error from inside a suite.
if [ "$clean" != 1 ]; then
    unreadable=$(find "$SOURCE" -path "$SOURCE/.git" -prune -o \
        -type f ! -perm -o=r -print 2>/dev/null | head -n 3)
    if [ -n "$unreadable" ]; then
        printf 'verify: NOTE these files are not world-readable, and the images run\n'
        printf '        as a non-root user, so a smoke may fail to read them:\n'
        printf '%s\n' "$unreadable" | sed 's/^/        /'
        printf '        (chmod -R a+rX %s, or use --clean)\n' "$SOURCE"
    fi
fi

printf 'verify: repository %s\n' "$REPO"
printf 'verify: targets %s\n' "$targets"
if [ "$clean" = 1 ]; then
    printf 'verify: source %s (git archive of HEAD)\n' "$SOURCE"
else
    printf 'verify: source %s (work tree)\n' "$SOURCE"
fi

for target in $targets; do
    case " $HEAVY_TARGETS " in
        *" $target "*) skip_target "$target" ;;
        *) run_target "$target" ;;
    esac
done

printf '\n== summary ==\n'
printf '%-16s %-26s %s\n' target image result
while read -r name image result detail; do
    if [ -n "${detail:-}" ]; then
        printf '%-16s %-26s %s %s\n' "$name" "$image" "$result" "$detail"
    else
        printf '%-16s %-26s %s\n' "$name" "$image" "$result"
    fi
done <"$SUMMARY"

printf '\npassed %s, failed %s, skipped %s\n' "$PASSED" "$FAILED" "$SKIPPED"
if [ "$FAILED" -ne 0 ]; then
    exit 1
fi

# A skip is not a pass.  `--only android` (or any invocation whose targets are
# all declared-only) builds nothing, so its exit status must not be 0: a CI step
# that reads "passed 0, failed 0, skipped 1" as success is testing the skip line
# rather than the image.  --allow-skip is the explicit way to say the skip is the
# whole point, and it is required rather than assumed.
if [ "$PASSED" -eq 0 ]; then
    if [ "$allow_skip" = 1 ]; then
        printf 'verify: 0 passed, %s skipped; --allow-skip was given, so exit 0\n' "$SKIPPED"
    else
        printf 'verify: 0 passed, %s skipped: nothing was built and nothing was proved\n' \
            "$SKIPPED" >&2
        printf 'verify: a skipped target is not a pass; re-run with --allow-skip if a\n' >&2
        printf '        declared-only target is what you meant to check.\n' >&2
        exit 1
    fi
fi
