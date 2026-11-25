#!/usr/bin/env python3
"""Install owner-controlled SSH on an E64 WS grinder through the ESP upload path.

The shipped `upload_esp.php` accepts a ZIP without authentication, extracts it
to /tmp/esp and executes the archive-provided `do_flash.sh` as root through
`flashEspZip.sh`. This tool packages that script so it installs a static
dropbear daemon, an owner authorized key and an init script, then reports the
result.

Preconditions (all present on the shipped firmware):
  - /log is writable by www-data (factory logdata partition is chmod 777)
  - www-data has passwordless sudo (SEC-03)
  - /dev/ttySTM5 exists (ESP flash port)
  - the app partition supplies /usr/local/bin/flashEspZip.sh

Usage:
  esp_root.py --host 192.168.1.50 --pubkey ~/.ssh/id_ed25519.pub --dropbear ./dropbear
  esp_root.py --host ... --dry-run          # build the ZIP, do not upload
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import pathlib
import ssl
import sys
import time
import urllib.request
import zipfile

INSTALLER = """#!/bin/sh
# Owner installer: runs as root from flashEspZip.sh.
#
# ESP safety: flashEspZip.sh has already pulsed the ESP into bootloader mode
# (gpio60=0, gpio59 reset pulse) before running this script. Restore normal
# boot mode before doing anything else, and restore it again on any exit path.
# This script never opens /dev/ttySTM5 and never writes ESP flash.
set -x
restore_esp() {
  [ -x /usr/local/bin/unsetEspBootmode.sh ] && /usr/local/bin/unsetEspBootmode.sh
  # Belt and braces: the vendor script is the same sequence, repeated inline so a
  # missing helper cannot leave the ESP held in reset/download mode.
  [ -d /sys/class/gpio/gpio60 ] && echo 0 > /sys/class/gpio/gpio60/value 2>/dev/null
  [ -d /sys/class/gpio/gpio59 ] && echo 1 > /sys/class/gpio/gpio59/value 2>/dev/null
  [ -d /sys/class/gpio/gpio60 ] && echo 1 > /sys/class/gpio/gpio60/value 2>/dev/null
}
trap restore_esp EXIT INT TERM HUP
restore_esp
mount -o remount,rw / 2>/dev/null
mkdir -p /etc/dropbear /root/.ssh /run
cp /tmp/esp/*/dropbear /usr/sbin/dropbear 2>/dev/null || cp "$(dirname "$0")/dropbear" /usr/sbin/dropbear
chmod 755 /usr/sbin/dropbear
cat > /root/.ssh/authorized_keys <<'KEY'
__PUBKEY__
KEY
chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
cat > /etc/init.d/S85dropbear <<'INIT'
#!/bin/sh
case "$1" in
start) mkdir -p /etc/dropbear /run; start-stop-daemon -S -q -b -x /usr/sbin/dropbear -- -R -p 22 ;;
stop) killall -q dropbear ;;
esac
exit 0
INIT
chmod 755 /etc/init.d/S85dropbear
/etc/init.d/S85dropbear start
restore_esp
echo "owner installer complete" > /root/esp_root_result
id >> /root/esp_root_result
echo "esp gpio59=$(cat /sys/class/gpio/gpio59/value 2>/dev/null)" >> /root/esp_root_result
echo "esp gpio60=$(cat /sys/class/gpio/gpio60/value 2>/dev/null)" >> /root/esp_root_result
"""


def build_zip(pubkey: str, dropbear: pathlib.Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        installer = INSTALLER.replace("__PUBKEY__", pubkey.strip())
        info = zipfile.ZipInfo("payload/do_flash.sh")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, installer)
        info = zipfile.ZipInfo("payload/dropbear")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, dropbear.read_bytes())
    return buffer.getvalue()


def upload(host: str, payload: bytes, insecure: bool, timeout: int) -> str:
    boundary = "----e64owner" + base64.b16encode(os.urandom(8)).decode()
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="espFile"; filename="payload.zip"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    request = urllib.request.Request(
        f"https://{host}/upload_esp.php",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read().decode(errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--pubkey-file", required=True)
    parser.add_argument("--dropbear", required=True, type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--zip-out", type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--ssh-host", default=None)
    parser.add_argument("--ssh-port", type=int, default=22)
    args = parser.parse_args()

    ssh_host = args.ssh_host or args.host.split(":")[0]
    pubkey = pathlib.Path(args.pubkey_file).read_text()
    payload = build_zip(pubkey, args.dropbear)
    if args.zip_out:
        args.zip_out.write_bytes(payload)
    print(f"payload: {len(payload)} bytes")
    if args.dry_run:
        print("dry run: not uploading")
        return 0

    print(f"uploading to https://{args.host}/upload_esp.php (no authentication)")
    reply = upload(args.host, payload, insecure=True, timeout=args.timeout)
    print(reply.strip()[:400])
    if "Upload successful" not in reply:
        print("upload rejected; the chain did not start", file=sys.stderr)
        return 1

    print("payload started; waiting for dropbear")
    for attempt in range(10):
        time.sleep(3)
        try:
            import socket

            with socket.create_connection((ssh_host, args.ssh_port), timeout=3):
                print(f"SSH is up on {ssh_host}:{args.ssh_port} after {(attempt + 1) * 3}s")
                return 0
        except OSError:
            continue
    print("dropbear did not answer on :22; check /root/esp_root_result on the device", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
