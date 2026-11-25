#!/bin/sh
# Procedure-level checks for the R2/R4/R8 recovery rehearsals.
#
#   sh tests/rehearse_recovery.sh
#
# The rehearsals in docs/evidence/recovery/ need the QEMU VM. This script runs
# the same three procedures against the POSIX boot-script model in boot.scr and
# asserts the outcome each rehearsal is supposed to test. It needs no VM, no
# firmware and no network, so it can run in CI.
#
# What it cannot check: that U-Boot really sources boot.scr, that a real reset
# selects the other slot, or that /proc/cmdline carries booted_system. Those
# remain hardware-only, as docs/evidence/recovery/README.md states.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HARNESS="$HERE/../boot.scr"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vg-rehearse.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

FW=$WORK/fw
mkdir -p "$FW"

# Stand-ins for the vendor scripts: only the slot default on line 6 differs in
# the real pair, and the model compares byte content, so two distinct payloads
# are enough here.
printf 'setenv bootsystem A\n' >"$FW/bootA.scr"
printf 'setenv bootsystem B\n' >"$FW/bootB.scr"
cp "$FW/bootA.scr" "$FW/boot.scr"

pass=0
fail=0

run() { # run <expected-substring> <rdev> <args...>
    want=$1; rdev=$2
    shift 2
    out=$(BOOT_FIRMWARE_DIR=$FW BOOT_RDEV=$rdev sh "$HARNESS" "$@" 2>&1) || true
    case $out in
        *"$want"*) pass=$((pass + 1)) ;;
        *)
            fail=$((fail + 1))
            printf 'FAIL: boot.scr %s\n  wanted: %s\n  got:\n%s\n' \
                "$*" "$want" "$out" >&2
            ;;
    esac
}

env_has() { # env_has <key> <value>
    got=$(BOOT_FIRMWARE_DIR=$FW sh "$HARNESS" status | sed -n "s/^  ${1}=//p")
    if [ "$got" = "$2" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL: env %s is %s, wanted %s\n' "$1" "${got:-<unset>}" "$2" >&2
    fi
}

# ---------------------------------------------------- R2: slot selection

# The manual switch is a plain copy; it must not create a rollback backup.
cp "$FW/bootB.scr" "$FW/boot.scr"
run 'Active slot: B' /dev/mmcblk1p5 status
if [ -e "$FW/rollback.scr" ]; then
    fail=$((fail + 1))
    printf 'FAIL: R2 plain copy created rollback.scr\n' >&2
else
    pass=$((pass + 1))
fi
# boot.scr:4 runs do_rollback unconditionally; with no rollback.scr the boot
# still proceeds normally.
run 'do_rollback runs: yes' /dev/mmcblk1p5 predict
run 'next boot: normal boot (rollback.scr absent)' /dev/mmcblk1p5 predict

# ------------------------------------- R4: arming is not verification

run 'ustate set to 1' /dev/mmcblk1p5 select B --ustate 1 --dest-dev /dev/mmcblk1p5
# A reboot runs no verification of its own: the state is unchanged.
run 'ustate=1' /dev/mmcblk1p5 status
env_has ustate 1
run 'Verification PASS' /dev/mmcblk1p5 verify
env_has ustate 2
if [ -e "$FW/rollback.scr" ]; then
    fail=$((fail + 1))
    printf 'FAIL: R4 pass branch kept rollback.scr\n' >&2
else
    pass=$((pass + 1))
fi

# --------------------------------------------- R8: rollback on mismatch

run 'Installed bootA.scr' /dev/mmcblk1p4 install A
cp "$FW/boot.scr" "$FW/rollback.scr"
run 'ustate set to 1' /dev/mmcblk1p4 select B --ustate 1 --dest-dev /dev/mmcblk1p4
run 'Active slot: B' /dev/mmcblk1p4 status
# Slot B booted, dest_dev says A: mismatch, so the backup is restored.
run 'Verification FAIL' /dev/mmcblk1p5 verify
env_has ustate 3
if cmp -s "$FW/boot.scr" "$FW/bootA.scr"; then
    pass=$((pass + 1))
else
    fail=$((fail + 1))
    printf 'FAIL: R8 did not restore bootA.scr as boot.scr\n' >&2
fi
run 'Active slot: A' /dev/mmcblk1p5 status

# ------------------------------- R8 negative control: no backup to restore

run 'ustate set to 1' /dev/mmcblk1p4 select B --ustate 1 --dest-dev /dev/mmcblk1p4
if [ -e "$FW/rollback.scr" ]; then
    pass=$((pass + 1))
else
    fail=$((fail + 1))
    printf 'FAIL: the install hook did not create rollback.scr\n' >&2
fi
rm -f "$FW/rollback.scr"
# One call: it reports the mismatch, fails the move and stays at ustate=3.
out=$(BOOT_FIRMWARE_DIR=$FW BOOT_RDEV=/dev/mmcblk1p5 sh "$HARNESS" verify 2>&1) || true
for want in 'Verification FAIL' 'could not restore rollback.scr'; do
    case $out in
        *"$want"*) pass=$((pass + 1)) ;;
        *)
            fail=$((fail + 1))
            printf 'FAIL: negative control wanted "%s", got:\n%s\n' "$want" "$out" >&2
            ;;
    esac
done
env_has ustate 3
# The move failed, so boot.scr still points at the unverified slot.
if cmp -s "$FW/boot.scr" "$FW/bootB.scr"; then
    pass=$((pass + 1))
else
    fail=$((fail + 1))
    printf 'FAIL: R8 negative control changed boot.scr without a backup\n' >&2
fi

printf 'rehearse_recovery: %s checks passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
