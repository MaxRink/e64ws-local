#!/bin/sh
# Firmware-triage smoke test, executed inside the e64-firmware-triage image.
#
# Why a script instead of "docker run IMAGE bsdtar --version": a version banner
# does not notice a missing helper, and tools/firmware_triage.py answers
# "not observable" instead of failing when bsdtar or openssl is absent - exactly
# the degraded result that reads like a clean one.  So this drives the real
# path end to end:
#
#   1. build a signed .swu fixture with the repository's own generator
#      (tools/vm-swu/make_test_swu.py), which needs openssl and cpio;
#   2. list and extract the cpio members with bsdtar - the binary the triage
#      tool itself shells out to;
#   3. verify sw-description.sig with openssl, positive case ("Verified OK");
#   4. round-trip a file through an ext4 image with mke2fs + debugfs - the
#      e2fsprogs path that tools/virtual-grinder/from_swu.sh uses;
#   5. triage the fixture with tools/firmware_triage.py and assert the parsed
#      --json report, so the tool itself is covered, not just its dependencies;
#   6. feed the tool a non-cpio file and require exit 2.  Step 6 is what makes
#      the smoke load-bearing: a parser that accepted anything would still pass
#      steps 1-5.
#
# The fixture is signed with a throwaway key, so the triage verdict is FAIL
# (signature anchor mismatch) by design.  The smoke asserts the report
# structure and the refusal behaviour, never the verdict.
#
# Exit status: 0 when every required step passes, 1 on the first failure.
set -eu

REPO=${REPO:-/repo}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/fw-triage-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

fail() {
    printf 'SMOKE FAIL: %s\n' "$1" >&2
    exit 1
}

ok() {
    printf 'SMOKE OK: %s\n' "$1"
}

printf '== toolchain ==\n'
bsdtar --version
openssl version
mke2fs -V 2>&1 | head -2
python3 -VV

printf '\n== 1. build a signed .swu fixture with the repository generator ==\n'
python3 "$REPO/tools/vm-swu/make_test_swu.py" --out "$WORK/pkg" >"$WORK/make.log" 2>&1 \
    || { cat "$WORK/make.log" >&2; fail "make_test_swu.py did not produce a fixture"; }
sed -n '1,4p' "$WORK/make.log"
SWU=$WORK/pkg/test-update.swu
[ -s "$SWU" ] || fail "fixture is missing or empty: $SWU"

printf '\n== 2. bsdtar reads the cpio stream ==\n'
bsdtar -tf "$SWU" >"$WORK/members.txt" || fail "bsdtar could not list $SWU"
cat "$WORK/members.txt"
count=$(wc -l <"$WORK/members.txt" | tr -d ' ')
[ "$count" = "3" ] || fail "expected 3 cpio members, got $count"
grep -qx 'sw-description' "$WORK/members.txt" || fail "sw-description is not a member"
bsdtar -xf "$SWU" -C "$WORK/pkg" || fail "bsdtar could not extract the fixture"
ok "bsdtar listed and extracted 3 members"

printf '\n== 3. openssl verifies the fixture signature (positive case) ==\n'
openssl dgst -sha256 -verify "$WORK/pkg/test-signing.pub" \
    -signature "$WORK/pkg/sw-description.sig" "$WORK/pkg/sw-description" \
    >"$WORK/verify.txt" 2>&1 \
    || { cat "$WORK/verify.txt" >&2; fail "openssl rejected a signature it had just produced"; }
cat "$WORK/verify.txt"
grep -q 'Verified OK' "$WORK/verify.txt" || fail "openssl did not print Verified OK"

printf '\n== 4. e2fsprogs writes and reads an ext4 image ==\n'
mkdir -p "$WORK/rootfs/etc"
printf 'triage smoke\n' >"$WORK/rootfs/etc/marker"
mke2fs -q -t ext4 -d "$WORK/rootfs" "$WORK/payload.ext4" 8192 >"$WORK/mke2fs.log" 2>&1 \
    || { cat "$WORK/mke2fs.log" >&2; fail "mke2fs could not build an ext4 image"; }
debugfs -R 'cat /etc/marker' "$WORK/payload.ext4" >"$WORK/cat.txt" 2>"$WORK/cat.err" \
    || { cat "$WORK/cat.err" >&2; fail "debugfs could not read the ext4 image"; }
grep -q 'triage smoke' "$WORK/cat.txt" || fail "debugfs returned the wrong file content"
debugfs -R 'stat /etc/marker' "$WORK/payload.ext4" 2>/dev/null | sed -n '1,2p'
ok "mke2fs + debugfs round-tripped a file through ext4"

printf '\n== 5. triage the fixture with the repository CLI ==\n'
if [ -f "$REPO/tools/firmware_triage.py" ]; then
    set +e
    python3 "$REPO/tools/firmware_triage.py" "$SWU" --json "$WORK/report.json" \
        >"$WORK/triage.txt" 2>&1
    status=$?
    set -e
    sed -n '1,6p' "$WORK/triage.txt"
    case $status in
        0 | 1) : ;;
        *) cat "$WORK/triage.txt" >&2; fail "firmware_triage.py exited $status on a valid package" ;;
    esac
    [ -f "$WORK/report.json" ] || fail "firmware_triage.py wrote no --json report"
    python3 - "$WORK/report.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
package = report["package"]
assert package["cpio"] == "newc", package["cpio"]
assert package["member_count"] == 3, package["member_count"]
assert package["description"]["version"] == "1.16-24-test", package["description"]
verdict = report["verdict"]
# The report shape is {"overall": ..., "categories": [...]}; pin the shape, not
# the verdict, because the fixture is signed with a throwaway key and the
# signature category is expected to fail against the vendor anchors.
assert verdict["overall"] in {"PASS", "WARN", "FAIL"}, verdict["overall"]
by_name = {entry["category"]: entry["status"] for entry in verdict["categories"]}
assert by_name.get("cpio") == "PASS", by_name
assert "signature" in by_name, sorted(by_name)
print(
    "triage report ok: "
    f"cpio={package['cpio']} members={package['member_count']} "
    f"overall={verdict['overall']} signature={by_name['signature']}"
)
PY
    ok "firmware_triage.py parsed the fixture and wrote a report"

    printf '\n== 6. triage must refuse a non-cpio file (negative case) ==\n'
    printf 'this is not a swupdate package\n' >"$WORK/bad.swu"
    set +e
    python3 "$REPO/tools/firmware_triage.py" "$WORK/bad.swu" >"$WORK/bad.txt" 2>&1
    bad_status=$?
    set -e
    sed -n '1,3p' "$WORK/bad.txt"
    if [ "$bad_status" != "2" ]; then
        fail "a non-cpio file must exit 2, got $bad_status"
    fi
    if grep -qi 'traceback' "$WORK/bad.txt"; then
        fail "a refusal must be a message, not a traceback"
    fi
    ok "firmware_triage.py refused a non-cpio file with exit 2"
else
    printf 'SMOKE SKIP: tools/firmware_triage.py is not in this working tree\n'
    printf '            (untracked at the time of writing); steps 5 and 6 not run.\n'
fi

printf '\nSMOKE OK: firmware-triage image is usable\n'
