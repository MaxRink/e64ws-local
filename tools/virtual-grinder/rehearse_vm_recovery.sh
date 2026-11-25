#!/bin/sh
# Recovery rehearsals R2/R4/R8 against the virtual grinder.
#
#   sh tools/virtual-grinder/rehearse_vm_recovery.sh [OUTDIR]
#
# Default OUTDIR is /tmp/vg-recovery.  Every transcript under OUTDIR is written
# by this script from the live VM; nothing in it is edited by hand.  The
# repository's evidence bundle is produced with:
#
#   VG_ROOT=/tmp/vg-r2r4r8 \
#     sh tools/virtual-grinder/rehearse_vm_recovery.sh docs/evidence/recovery
#
# Preconditions: a built tree (`vg build`) and the vendor extraction.  The
# script owns the VM lifecycle: stop, stage the A/B scripts and env.bin into the
# guest rootfs, boot, rehearse, stop.
#
# What this can and cannot exercise is documented in
# docs/evidence/recovery/README.md.  The VM boots the kernel directly with
# `-kernel`; there is no U-Boot, no FAT p1 and no `booted_system=` in
# /proc/cmdline.  The U-Boot half of each rehearsal is therefore recorded as a
# negative observation plus a POSIX model run; the Linux half (fw_setenv,
# fw_printenv, S30verifyupdate) runs for real inside the vendor rootfs.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
VG="$HERE/vg"
OUT=${1:-/tmp/vg-recovery}

: "${VG_ROOT:=/tmp/virtual-grinder}"
E64_FW_DIR=${E64_FW_DIR:-$REPO/.tools/firmware-1.16-24}
E64_QEMU_DIR=${E64_QEMU_DIR:-$REPO/.tools/qemu}
export VG_ROOT E64_FW_DIR E64_QEMU_DIR

ROOTFS_IMG=$VG_ROOT/work/images/rootfs.ext2
SERIAL_LOG=$VG_ROOT/work/serial.log
QEMU_LOG=$VG_ROOT/work/qemu.log
FW=$E64_FW_DIR/raw

DEBUGFS=${DEBUGFS:-$(command -v debugfs 2>/dev/null ||
    echo /opt/homebrew/opt/e2fsprogs/sbin/debugfs)}
E2FSCK=${E2FSCK:-$(command -v e2fsck 2>/dev/null ||
    echo /opt/homebrew/opt/e2fsprogs/sbin/e2fsck)}

die() { echo "rehearse: $*" >&2; exit 1; }

mkdir -p "$OUT" || die "cannot create $OUT"

# Remove transcripts from an earlier run so a run that stops early cannot leave
# a stale result behind.  README.md and build.txt are not produced here.
rm -f "$OUT/environment.txt" "$OUT/staging.txt" "$OUT/shutdown-initial.txt" \
    "$OUT/boot.txt" "$OUT/harness-model.txt" "$OUT/teardown.txt" \
    "$OUT/r2/transcript.txt" "$OUT/r2/serial-window.txt" \
    "$OUT/r4/transcript.txt" "$OUT/r4/serial-window.txt" \
    "$OUT/r8/transcript.txt" "$OUT/r8/serial-window.txt"

# ------------------------------------------------------------------ helpers

# vg <args...>: run the CLI, echo the command and its exit status.
vg() {
    printf '$ vg %s\n' "$*"
    "$VG" "$@" 2>&1
    printf '[exit %s]\n' "$?"
}

# guest <command>: run a command in the guest and report the *guest* exit
# status.  `vg shell` exits 0 whenever the agent answers and truncates the reply
# at 5999 bytes, so the status has to be printed from inside the guest.
guest() {
    printf '\n$ vg shell %s\n' "$1"
    "$VG" shell "$1; echo \"[guest exit \$?\"]" 2>&1 || true
}

# header <file> <title>: start a transcript.
header() {
    : >"$1"
    printf '# %s\n# generated %s by tools/virtual-grinder/rehearse_vm_recovery.sh\n# VG_ROOT=%s\n\n' \
        "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$VG_ROOT" >>"$1"
}

# wait_boot: bounded poll for the guest agent, as written in the procedure.
# A lost daemon aborts the run: a partially recorded rehearsal must never look
# like a completed one.
wait_boot() {
    i=0
    while [ "$i" -lt 60 ]; do
        if "$VG" shell true >/dev/null 2>&1; then
            printf 'guest agent reachable after %s poll(s)\n' "$i"
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    printf 'guest agent NOT reachable after 60 polls\n'
    die "the guest agent never came back after the reset (see $OUT/boot.txt)"
}

# need_vm <where>: abort unless the daemon answers.
need_vm() {
    "$VG" shell true >/dev/null 2>&1 ||
        die "lost the VM before $1; the transcripts are incomplete"
}

serial_offset() {
    if [ -f "$SERIAL_LOG" ]; then wc -c <"$SERIAL_LOG" | tr -d ' '; else echo 0; fi
}

# serial_window <file> <start-byte> <title>: copy the bytes the serial console
# produced between two offsets.  The window is exact; a partial first line is
# dropped and the offsets are recorded so the trim is auditable.
serial_window() {
    file=$1; start=$2; title=$3
    end=$(serial_offset)
    {
        printf '# SERIAL WINDOW: %s\n' "$title"
        printf '# source: %s\n' "$SERIAL_LOG"
        printf '# bytes %s..%s of %s; leading partial line removed\n' \
            "$start" "$end" "$end"
        printf '# The guest agent logs every polled command, so `vg-agent: cmd: state`\n'
        printf '# repeats; it is kept because the trim is a byte range, not a filter.\n\n'
    } >"$file"
    if [ "$end" -gt "$start" ]; then
        # tail -c +N is 1-based: start+1 is the first byte after the offset.
        tail -c +$((start + 1)) "$SERIAL_LOG" | sed '1d' >>"$file"
    fi
}

# stop_vm <file>: shut the guest down cleanly, then stop the daemon.  A QMP
# quit on a running guest leaves the ext4 journal dirty; replaying that journal
# after a debugfs edit silently reverts the edit, so the guest is powered off
# through the agent first.
# qemu_procs: the VM processes, one short line each (the full QEMU command line
# is long and carries the workstation paths that the transcripts must not hold).
qemu_procs() {
    if [ -z "$(pgrep -f vg-qemu 2>/dev/null)" ]; then
        printf '(none)\n'
    else
        pgrep -fl vg-qemu | cut -c1-100
    fi
}

stop_vm() {
    file=$1; detail=${2:-brief}
    {
        if [ "$detail" = "full" ]; then
            printf '$ pgrep -fl vg-qemu (first 100 characters)\n'
            qemu_procs
        else
            printf '$ pgrep -f vg-qemu (before the agent poweroff)\n'
            qemu_procs
        fi
        printf '\n$ vg power shutdown\n'
        "$VG" power shutdown 2>&1
        printf '[exit %s]\n\n' "$?"
        i=0
        while [ "$i" -lt 30 ] && pgrep -f vg-qemu >/dev/null 2>&1; do
            i=$((i + 1))
            sleep 1
        done
        printf 'QEMU gone after %s s: %s\n\n' "$i" \
            "$(pgrep -f vg-qemu >/dev/null 2>&1 && echo no || echo yes)"
        printf '$ vg down\n'
        "$VG" down 2>&1
        printf '[exit %s]\n\n' "$?"
        printf '$ pgrep -fl vg-qemu (after vg down)\n'
        qemu_procs
        printf '\n$ grep -E "QEMU|stopping" work/daemon.log   (exit status, if the daemon logged it)\n'
        grep -E 'QEMU|stopping' "$VG_ROOT/work/daemon.log" | tail -4
    } >>"$file" 2>&1
}

# stage <file>: put the A/B scripts and the vendor env.bin into the guest's
# /boot/firmware, exactly as the rehearsal precondition requires.  Done on the
# image file with debugfs while the VM is down: a real unit ships them on FAT
# p1, the VM has no p1, so they live in the root filesystem.
#
# The image is fscked *before* the edit as well: the guest mounts it read-write,
# and a journal left dirty by an earlier stop is replayed on the next check,
# which would discard anything debugfs wrote in between.  Sizes are verified
# afterwards, so a reverted stage fails loudly instead of producing a
# rehearsal against an empty /boot/firmware.
stage() {
    file=$1
    script=$(mktemp "${TMPDIR:-/tmp}/vg-debugfs.XXXXXX") || die "mktemp failed"
    (
        for pair in \
            "images.standard.bootA.scr bootA.scr 0100755" \
            "images.standard.bootB.scr bootB.scr 0100755" \
            "env.bin env.bin 0100644" \
            "images.standard.bootA.scr boot.scr 0100755"; do
            set -- $pair
            printf 'rm /boot/firmware/%s\n' "$2"
            printf 'write raw/%s /boot/firmware/%s\n' "$1" "$2"
            printf 'sif /boot/firmware/%s mode %s\n' "$2" "$3"
        done
        printf 'rm /boot/firmware/rollback.scr\n'
    ) >"$script"
    {
        printf '# debugfs writes run with cwd=$E64_FW_DIR, so the script shows\n'
        printf '# vendor-relative names. `rm` on a missing file is expected on the\n'
        printf '# first run and does not fail the script.\n\n'
        printf '$ e2fsck -fy %s        # replay any journal from the last boot\n' "$ROOTFS_IMG"
        "$E2FSCK" -fy "$ROOTFS_IMG" >"$script.ck" 2>&1
        ck=$?
        tail -2 "$script.ck"
        printf '[exit %s]  (1 means the filesystem was modified; that is expected\n' "$ck"
        printf '              and is not a failure)\n\n'
        printf '$ cd "$E64_FW_DIR" && debugfs -w -f <script> %s\n' "$ROOTFS_IMG"
        sed 's/^/  | /' "$script"
        (cd "$E64_FW_DIR" && "$DEBUGFS" -w -f "$script" "$ROOTFS_IMG" 2>&1)
        printf '[exit %s]\n\n' "$?"
        printf '$ e2fsck -fy %s\n' "$ROOTFS_IMG"
        "$E2FSCK" -fy "$ROOTFS_IMG" >"$script.ck" 2>&1
        ck=$?
        tail -2 "$script.ck"
        printf '[exit %s]\n\n' "$ck"
        printf '$ debugfs -R "stat /boot/firmware/<file>"  (verify the stage held)\n'
        failed=0
        for pair in \
            "bootA.scr 1709" "bootB.scr 1709" \
            "env.bin 131072" "boot.scr 1709"; do
            set -- $pair
            size=$("$DEBUGFS" -R "stat /boot/firmware/$1" "$ROOTFS_IMG" 2>&1 |
                awk '/^User:/ {for (i = 1; i <= NF; i++) if ($i == "Size:") {print $(i + 1); exit}}')
            printf '  %-12s %s bytes (expected %s)\n' "$1" "${size:-missing}" "$2"
            [ "${size:-}" = "$2" ] || failed=1
        done
        if [ "$failed" -ne 0 ]; then
            rm -f "$script" "$script.ck"
            die "staging did not survive the second fsck; see $file"
        fi
    } >>"$file"
    rm -f "$script" "$script.ck"
}

require_vm() {
    "$VG" shell true >/dev/null 2>&1 || die "the guest agent is not answering"
}

# ----------------------------------------------------------------- preflight

[ -f "$ROOTFS_IMG" ] || die "missing $ROOTFS_IMG; run vg build first"
for f in images.standard.bootA.scr images.standard.bootB.scr env.bin; do
    [ -f "$FW/$f" ] || die "missing vendor file $FW/$f"
done

{
    printf '# Build and tool record for the recovery rehearsals\n'
    printf '# generated %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '## Host\n\n'
    printf '%-18s %s\n' "uname" "$(uname -srm)"
    printf '%-18s %s\n' "macOS" "$(sw_vers -productVersion 2>/dev/null || echo n/a)"
    printf '%-18s %s\n' "python3" "$(python3 -VV 2>&1 | tr '\n' ' ')"
    printf '%-18s %s\n' "qemu-system-arm" "$(qemu-system-arm --version 2>&1 | head -1)"
    printf '%-18s %s\n' "dtc" "$(dtc --version 2>&1 | head -1)"
    printf '%-18s %s\n' "debugfs" "$("$DEBUGFS" -V 2>&1 | head -1)"
    printf '%-18s %s\n' "e2fsck" "$("$E2FSCK" -V 2>&1 | head -1)"
    printf '\n## Rehearsal environment\n\n'
    printf '%-18s %s\n' "VG_ROOT" "$VG_ROOT"
    printf '%-18s %s\n' "E64_FW_DIR" "$E64_FW_DIR"
    printf '%-18s %s\n' "E64_QEMU_DIR" "$E64_QEMU_DIR"
    printf '\n## Input hashes (SHA-256)\n\n'
    for f in \
        "$FW/images.standard.bootA.scr" \
        "$FW/images.standard.bootB.scr" \
        "$FW/env.bin" \
        "$E64_FW_DIR/rootfs.ext2" \
        "$E64_FW_DIR/app_image.ext4" \
        "$E64_QEMU_DIR/kernel/vmlinuz" \
        "$E64_QEMU_DIR/kernel/initrd-img"; do
        printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "${f#$REPO/}"
    done
    printf '\n## Built artifacts (SHA-256)\n\n'
    for f in "$VG_ROOT"/work/images/*; do
        [ -f "$f" ] || continue
        printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"
    done
} >"$OUT/environment.txt" 2>&1

# --------------------------------------------------------------- lifecycle

# One rehearsal run per VG_ROOT.  Two drivers sharing a tree stop each other's
# VM, which silently truncates the first run's transcripts.
if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:28765 -sTCP:LISTEN >/dev/null 2>&1 || \
       lsof -nP -iTCP:28082 -sTCP:LISTEN >/dev/null 2>&1; then
        die "a virtual grinder is already listening on 28765/28082; stop it first"
    fi
fi

header "$OUT/shutdown-initial.txt" "Clean stop before staging (no QEMU running expected)"
stop_vm "$OUT/shutdown-initial.txt"

header "$OUT/staging.txt" "Stage the rehearsal preconditions (VM down)"
stage "$OUT/staging.txt"

{
    printf '$ vg up\n'
    "$VG" up 2>&1
    printf '[exit %s]\n\n' "$?"
} >"$OUT/boot.txt"
require_vm

{
    printf '# Guest view after the staged boot\n\n'
    printf '$ vg shell cat /proc/cmdline\n'
    "$VG" shell 'cat /proc/cmdline'
    printf '\n$ vg shell ls -la /boot/firmware\n'
    "$VG" shell 'ls -la /boot/firmware'
    printf '\n$ vg shell sha256sum /boot/firmware/*\n'
    "$VG" shell 'sha256sum /boot/firmware/*'
    printf '\n$ vg shell mount "|" grep firmware\n'
    "$VG" shell 'mount | grep firmware; echo "[guest exit $?]"'
    printf '\n$ vg shell rdev\n'
    "$VG" shell 'rdev; echo "[guest exit $?]"'
    printf '\n$ vg shell fw_printenv\n'
    "$VG" shell 'fw_printenv; echo "[guest exit $?]"'
    printf '\n# mountdata.sh reports that the VM has no FAT p1 to mount:\n'
    printf '$ grep -n "Firmware Device" %s\n' "$SERIAL_LOG"
    grep -n "Firmware Device" "$SERIAL_LOG"
    printf '\n# No U-Boot in the boot path:\n'
    printf '$ grep -c -i "u-boot\\|booted_system" %s\n' "$SERIAL_LOG"
    grep -c -i "u-boot\|booted_system" "$SERIAL_LOG"
    printf '\n# `vg shell` exits 0 even when the guest command fails, so the\n'
    printf '# transcripts below print the guest status from inside the guest:\n'
    printf '$ vg shell false; echo "host exit $?"\n'
    "$VG" shell 'false'
    printf 'host exit %s\n' "$?"
    printf '\n# `vg shell` truncates the reply (vg-agent.c: char out[6000]);\n'
    printf '# a 3000-line reply ends around line 1500 instead of 3000:\n'
    printf '$ vg shell "seq 1 3000" | tail -2\n'
    "$VG" shell 'seq 1 3000' | tail -2
    printf '\n# The kernel command line says root=/dev/vda but the vendor\n'
    printf '# initramfs mounts whichever disk holds /sbin/init; rdev shows the\n'
    printf '# real root. Neither matches the documented eMMC layout:\n'
    printf '$ vg shell "cat /proc/cmdline; rdev; cat /proc/partitions"  (trimmed)\n'
    "$VG" shell 'cat /proc/cmdline; rdev; grep -c . /proc/partitions'
} >>"$OUT/boot.txt"

# --------------------------------------------------------------------- R2

R2=$OUT/r2
mkdir -p "$R2"
T=$R2/transcript.txt
need_vm "the R2 transcript"
header "$T" "R2 boot slot selection via boot.scr (as written)"
s0=$(serial_offset)
{
    printf '## Precondition\n\n'
    vg status
    printf '\n$ wait_boot (not needed here; the agent is up after vg up)\n\n'
    guest 'ls -la /boot/firmware'
    guest 'cat /proc/cmdline | grep booted_system'
    guest 'sha256sum /boot/firmware/boot.scr /boot/firmware/bootA.scr /boot/firmware/bootB.scr'
    guest 'fw_printenv ustate'
    guest 'cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime'
    printf '## Switch to slot B by installing bootB.scr as boot.scr\n\n'
    guest 'cp /boot/firmware/bootB.scr /boot/firmware/boot.scr && sync'
    guest 'sha256sum /boot/firmware/boot.scr'
    vg power reset
    printf '$ wait_boot\n'
    wait_boot
    need_vm "the post-reset checks"
    printf '\n## A different boot_id and a smaller uptime prove the guest rebooted\n\n'
    guest 'cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime'
    printf '\n## Verify slot B boots\n\n'
    guest 'cat /proc/cmdline | grep booted_system'
    guest 'cat /proc/cmdline'
    guest 'sha256sum /boot/firmware/boot.scr /boot/firmware/bootA.scr /boot/firmware/bootB.scr'
    guest 'fw_printenv ustate'
    guest 'rdev'
    printf '## Supplementary: the switch changed only the file, not the boot\n\n'
    guest 'cmp -s /boot/firmware/boot.scr /boot/firmware/bootB.scr; echo "boot.scr==bootB.scr exit $?"'
    guest 'cmp -s /boot/firmware/boot.scr /boot/firmware/bootA.scr; echo "boot.scr==bootA.scr exit $?"'
} >>"$T" 2>&1
serial_window "$R2/serial-window.txt" "$s0" "R2: boot.scr switched to B, QMP reset"

# --------------------------------------------------------------------- R4

# poll_ustate <label> <polls> <interval>: watch ustate, boot.scr and
# rollback.scr from the host without touching the guest.  One row per poll.
poll_ustate() {
    label=$1; count=${2:-24}; interval=${3:-5}
    printf '# %s\n' "$label"
    printf '# (read over the control channel only; no guest command arms anything)\n'
    printf '# poll  uptime  ustate  boot.scr  rollback.scr\n'
    i=0
    while [ "$i" -lt "$count" ]; do
        i=$((i + 1))
        uptime=$("$VG" shell 'cut -c1-6 /proc/uptime' 2>/dev/null |
            tr -d ' \n')
        ustate=$("$VG" shell 'fw_printenv -n ustate 2>/dev/null || echo -' 2>/dev/null |
            tr -d ' \n')
        boot=$("$VG" shell 'sha256sum /boot/firmware/boot.scr 2>/dev/null | cut -c1-8' 2>/dev/null |
            tr -d ' \n')
        rb=$("$VG" shell 'test -e /boot/firmware/rollback.scr && echo present || echo absent' 2>/dev/null |
            tr -d ' \n')
        if [ -z "$uptime$ustate$boot$rb" ]; then
            printf '  %-5s no answer from the guest; aborting\n' "$i"
            die "lost the VM during a poll; the transcripts are incomplete"
        fi
        printf '  %-5s %-7s %-6s %-9s %s\n' "$i" "${uptime:-?}" "${ustate:-?}" \
            "${boot:-?}" "${rb:-?}"
        sleep "$interval"
    done
    printf '\n'
}

R4=$OUT/r4
mkdir -p "$R4"
T=$R4/transcript.txt
need_vm "the R4 transcript"
header "$T" "R4 ustate=1 fix and verification (as written)"
s0=$(serial_offset)
{
    printf '## Arm the update and install slot B\n\n'
    guest 'fw_setenv ustate 1 && fw_setenv dest_dev /dev/mmcblk1p5 && cp /boot/firmware/bootB.scr /boot/firmware/boot.scr && sync'
    guest 'fw_printenv ustate dest_dev'
    guest 'cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime'
    vg power reset
    printf '$ wait_boot\n'
    wait_boot
    need_vm "the post-reset checks"
    printf '\n## As written: did S30verifyupdate force run and clear ustate?\n'
    guest 'cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime'
    guest 'fw_printenv ustate'
    guest 'fw_printenv dest_dev'
    guest 'rdev'
} >>"$T" 2>&1

poll_ustate "R4: ustate over the two minutes after the reboot" 24 5 >>"$T" 2>&1

{
    printf '## The transition is not caused by the host\n\n'
    printf '# The poll above is read-only. Something inside the guest ran\n'
    printf '# /etc/init.d/S30verifyupdate force after the agent came back.\n'
    guest 'fw_printenv ustate dest_dev'
    guest 'pidof NgxUiApp'
    guest 'ls -l /etc/init.d/S30verifyupdate; grep -c verifyupdate /etc/init.d/rcS'
    guest 'ls -la /boot/firmware'
    printf '\n## Causal check: freeze the HMI, then resume it\n\n'
    printf '# Same armed state as above, but NgxUiApp is sent SIGSTOP as soon as\n'
    printf '# it exists, so it cannot call force.\n'
    guest 'cp /boot/firmware/bootA.scr /boot/firmware/boot.scr; cp /boot/firmware/boot.scr /boot/firmware/rollback.scr; fw_setenv ustate 1; fw_setenv dest_dev /dev/mmcblk1p4; cp /boot/firmware/bootB.scr /boot/firmware/boot.scr; sync; echo armed'
    vg power reset
    printf '$ wait for pidof NgxUiApp, then kill -STOP\n'
    i=0
    pid=""
    while [ "$i" -lt 60 ]; do
        i=$((i + 1))
        pid=$("$VG" shell 'pidof NgxUiApp' 2>/dev/null | tr -d ' \n')
        [ -n "$pid" ] && break
        sleep 1
    done
    printf 'NgxUiApp pid after %s s: %s\n' "$i" "${pid:-NOT FOUND}"
} >>"$T" 2>&1

if [ -z "$pid" ]; then
    printf '\nNgxUiApp never appeared; the causal check was not run.\n' >>"$T"
else
    {
        guest "kill -STOP $pid; echo stopped"
        guest "awk '/^State:/{print \"state \" \$2}' /proc/$pid/status"
    } >>"$T" 2>&1
    poll_ustate "R4: HMI frozen (SIGSTOP); nothing else calls force" 14 6 >>"$T" 2>&1
    {
        guest "kill -CONT $pid; echo resumed"
        guest "awk '/^State:/{print \"state \" \$2}' /proc/$pid/status"
    } >>"$T" 2>&1
    poll_ustate "R4: HMI resumed (SIGCONT); the transition happens again" 10 6 >>"$T" 2>&1
fi

{
    printf '## Isolate the script from the HMI: run force by hand\n\n'
    printf '### Literal R4 dest_dev (/dev/mmcblk1p5) against the VM root device\n\n'
    guest 'fw_setenv ustate 1; fw_setenv dest_dev /dev/mmcblk1p5; sync'
    guest '/etc/init.d/S30verifyupdate force'
    guest 'fw_printenv ustate dest_dev'
    printf '\n### Pass branch with the VM root device substituted for the slot\n'
    printf '### device; the VM has no /dev/mmcblk1p4 or p5 to compare against\n\n'
    guest 'RDEV=$(rdev | cut -d" " -f1); fw_setenv ustate 1; fw_setenv dest_dev "$RDEV"; cp /boot/firmware/bootA.scr /boot/firmware/boot.scr; cp /boot/firmware/boot.scr /boot/firmware/rollback.scr; sync; echo "armed dest_dev=$RDEV"'
    guest 'fw_printenv ustate dest_dev; ls -la /boot/firmware'
    guest '/etc/init.d/S30verifyupdate force'
    guest 'fw_printenv ustate dest_dev; ls -la /boot/firmware'
    printf '\n### The inert path: force with ustate != 1\n\n'
    guest 'fw_setenv ustate 0; /etc/init.d/S30verifyupdate force; fw_printenv ustate'
} >>"$T" 2>&1
serial_window "$R4/serial-window.txt" "$s0" "R4: ustate=1 armed, QMP reset, HMI runs S30verifyupdate force"
{
    printf '\n## What rcS and the vendor script printed on the console\n\n'
    printf '$ grep -n "S30verifyupdate\\|Update Success\\|Rollback detected" r4/serial-window.txt\n'
    grep -n "S30verifyupdate\|Update Success\|Rollback detected" \
        "$R4/serial-window.txt" || printf '(no match)\n'
} >>"$T" 2>&1

# --------------------------------------------------------------------- R8

R8=$OUT/r8
mkdir -p "$R8"
T=$R8/transcript.txt
need_vm "the R8 transcript"
header "$T" "R8 rollback on mismatch (as written)"
s0=$(serial_offset)
{
    printf '## Put slot A in place and recreate the preinstall backup\n\n'
    guest 'cp /boot/firmware/bootA.scr /boot/firmware/boot.scr && cp /boot/firmware/boot.scr /boot/firmware/rollback.scr && sync'
    guest 'sha256sum /boot/firmware/boot.scr /boot/firmware/rollback.scr /boot/firmware/bootA.scr'
    printf '## Arm ustate=1 with dest_dev on the other slot, then install B\n\n'
    guest 'fw_setenv ustate 1 && fw_setenv dest_dev /dev/mmcblk1p4 && cp /boot/firmware/bootB.scr /boot/firmware/boot.scr && sync'
    guest 'fw_printenv ustate dest_dev'
    guest 'sha256sum /boot/firmware/boot.scr /boot/firmware/rollback.scr'
    guest 'cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime'
    vg power reset
    printf '$ wait_boot\n'
    wait_boot
    need_vm "the post-reset checks"
    printf '\n## As written: was rollback.scr restored on the reboot?\n'
    guest 'cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime'
    guest 'fw_printenv ustate'
    guest 'cmp /boot/firmware/boot.scr /boot/firmware/bootA.scr && echo "rollback to A" || echo "still B"'
    guest 'ls -la /boot/firmware'
} >>"$T" 2>&1

poll_ustate "R8: ustate, boot.scr and rollback.scr over two minutes" 24 5 >>"$T" 2>&1

{
    printf '## Final state after the guest ran verification on its own\n\n'
    guest 'fw_printenv ustate dest_dev'
    guest 'cmp /boot/firmware/boot.scr /boot/firmware/bootA.scr && echo "rollback to A" || echo "still B"'
    guest 'sha256sum /boot/firmware/boot.scr /boot/firmware/bootA.scr'
    guest 'ls -la /boot/firmware'
    printf '\n## Negative control: the same mismatch with no rollback.scr\n\n'
    printf '# The restore step is `mv rollback.scr boot.scr`.  Without the backup\n'
    printf '# the move fails, and the script does not test its status.\n'
    guest 'rm -f /boot/firmware/rollback.scr; fw_setenv ustate 1; fw_setenv dest_dev /dev/mmcblk1p4; cp /boot/firmware/bootB.scr /boot/firmware/boot.scr; sync; echo armed-without-rollback'
    vg power reset
    printf '$ wait_boot\n'
    wait_boot
    need_vm "the post-reset checks"
} >>"$T" 2>&1

poll_ustate "R8 negative control: mismatch without rollback.scr" 24 5 >>"$T" 2>&1

{
    guest 'fw_printenv ustate dest_dev'
    guest 'cmp /boot/firmware/boot.scr /boot/firmware/bootB.scr && echo "boot.scr still B" || echo "boot.scr changed"'
    guest 'ls -la /boot/firmware'
} >>"$T" 2>&1
serial_window "$R8/serial-window.txt" "$s0" "R8: rollback.scr staged, QMP reset, HMI runs S30verifyupdate force"
{
    printf '\n## What rcS and the vendor script printed on the console\n\n'
    printf '$ grep -n "S30verifyupdate\\|Update Success\\|Rollback detected" r8/serial-window.txt\n'
    grep -n "S30verifyupdate\|Update Success\|Rollback detected" \
        "$R8/serial-window.txt" || printf '(no match)\n'
} >>"$T" 2>&1

# redact_out: the transcripts must not carry workstation paths; the evidence
# manifests follow the same rule.  Rewrites every text file under OUT in place.
redact_out() {
    find "$OUT" -type f -name '*.txt' | while IFS= read -r f; do
        sed -e "s|$REPO|<checkout>|g" \
            -e "s|$E64_FW_DIR|<E64_FW_DIR>|g" \
            -e "s|$E64_QEMU_DIR|<E64_QEMU_DIR>|g" \
            -e "s|/private/tmp/|/tmp/|g" \
            -e "s|$HOME|~|g" "$f" >"$f.redacted" && mv "$f.redacted" "$f"
    done
}


# ----------------------------------------------------------- harness model

# The U-Boot half is not in the VM.  Replay the three procedures against the
# POSIX model in tools/virtual-grinder/boot.scr, over a copy of the exact
# scripts that were staged in the guest.
HA=$(mktemp -d "${TMPDIR:-/tmp}/vg-harness.XXXXXX") || die "mktemp failed"
mkdir -p "$HA/fw"
cp "$FW/images.standard.bootA.scr" "$HA/fw/bootA.scr"
cp "$FW/images.standard.bootB.scr" "$HA/fw/bootB.scr"
cp "$FW/images.standard.bootA.scr" "$HA/fw/boot.scr"

# hr <rdev> <boot.scr args...>
hr() {
    rdev=$1; shift
    printf '$ cd <scratch> && BOOT_FIRMWARE_DIR=fw BOOT_RDEV=%s sh boot.scr %s\n' "$rdev" "$*"
    (cd "$HA" && BOOT_FIRMWARE_DIR=fw BOOT_RDEV=$rdev sh "$HERE/boot.scr" "$@" 2>&1)
    printf '[exit %s]\n\n' "$?"
}

{
    printf '# R2/R4/R8 predicted by the POSIX boot-script model\n'
    printf '# generated %s by tools/virtual-grinder/rehearse_vm_recovery.sh\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# model: tools/virtual-grinder/boot.scr, a rehearsal aid and not U-Boot.\n'
    printf '# inputs: the same bootA.scr/bootB.scr staged in the guest\n'
    printf '#   %s  bootA.scr\n' "$(shasum -a 256 "$HA/fw/bootA.scr" | cut -d' ' -f1)"
    printf '#   %s  bootB.scr\n\n' "$(shasum -a 256 "$HA/fw/bootB.scr" | cut -d' ' -f1)"

    printf '### R2: install bootB.scr as boot.scr (a plain copy, no backup hook)\n\n'
    printf '$ cp fw/bootB.scr fw/boot.scr\n'
    cp "$HA/fw/bootB.scr" "$HA/fw/boot.scr"
    printf '[exit %s]\n\n' "$?"
    hr /dev/mmcblk1p5 status
    hr /dev/mmcblk1p5 predict

    printf '### R4: arm ustate=1 with dest_dev=/dev/mmcblk1p5, install B\n\n'
    hr /dev/mmcblk1p5 select B --ustate 1 --dest-dev /dev/mmcblk1p5
    hr /dev/mmcblk1p5 status
    printf '### R4: the model has no HMI, so a reboot runs no verify here (the VM does; see r4/)\n\n'
    hr /dev/mmcblk1p5 status
    printf '### R4: verify with slot B mounted (pass branch)\n\n'
    hr /dev/mmcblk1p5 verify
    hr /dev/mmcblk1p5 status

    printf '### R8: rollback.scr from A, dest_dev on A, then install B\n\n'
    hr /dev/mmcblk1p4 install A
    cp "$HA/fw/boot.scr" "$HA/fw/rollback.scr"
    printf '$ cp fw/boot.scr fw/rollback.scr\n[exit %s]\n\n' "$?"
    hr /dev/mmcblk1p4 select B --ustate 1 --dest-dev /dev/mmcblk1p4
    hr /dev/mmcblk1p4 status
    printf '### R8: verify from slot B (mismatch branch)\n\n'
    hr /dev/mmcblk1p5 verify
    hr /dev/mmcblk1p5 status

    printf '### R8 negative control: mismatch with rollback.scr absent\n\n'
    hr /dev/mmcblk1p5 select B --ustate 1 --dest-dev /dev/mmcblk1p4
    rm -f "$HA/fw/rollback.scr"
    printf '$ rm fw/rollback.scr\n\n'
    hr /dev/mmcblk1p5 verify
} >"$OUT/harness-model.txt" 2>&1
rm -rf "$HA"

# ------------------------------------------------------------- teardown

header "$OUT/teardown.txt" "Teardown: clean guest poweroff, then stop the daemon"
stop_vm "$OUT/teardown.txt" full
{
    printf '\n$ test -e %s/run/vg.pid\n' "$VG_ROOT"
    test -e "$VG_ROOT/run/vg.pid"
    printf '[exit %s]  (1 means the pid file was removed)\n\n' "$?"
    printf '# QEMU stdout/stderr. The exit status is the daemon.log line above;\n'
    printf '# vg status does not report it. An empty log means QEMU wrote nothing\n'
    printf '# to stdout/stderr, i.e. it did not fail noisily.\n\n'
    printf '$ wc -c < %s\n' "$QEMU_LOG"
    wc -c <"$QEMU_LOG"
} >>"$OUT/teardown.txt" 2>&1

# Redact last, so the model replay above is covered too.
redact_out

printf 'rehearsals written to %s\n' "$OUT"
