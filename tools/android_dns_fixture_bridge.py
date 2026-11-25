#!/usr/bin/env python3
"""Install/remove an exact emulator DNS-to-host fixture route."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def adb(serial: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["adb", "-s", serial, *args], check=check)


def ensure_root(serial: str) -> None:
    result = adb(serial, "root", check=False)
    if result.returncode != 0 or "cannot run as root" in (result.stdout + result.stderr).lower():
        raise RuntimeError("selected target is not a rootable emulator")
    adb(serial, "wait-for-device")
    if "uid=0(root)" not in adb(serial, "shell", "id").stdout:
        raise RuntimeError("adbd did not become root")


def rule(args: argparse.Namespace) -> list[str]:
    return [
        "-d", f"{args.device_dns}/32", "-p", "udp", "--dport", "53",
        "-j", "DNAT", "--to-destination", f"{args.host_gateway}:{args.host_port}",
    ]


def present(args: argparse.Namespace) -> bool:
    return adb(args.serial, "shell", "iptables", "-t", "nat", "-C", "OUTPUT", *rule(args), check=False).returncode == 0


def path(args: argparse.Namespace) -> Path:
    return args.state.expanduser().resolve()


def install(args: argparse.Namespace) -> None:
    ensure_root(args.serial)
    target = path(args)
    if target.exists():
        raise RuntimeError(f"state file already exists: {target}")
    if not present(args):
        adb(args.serial, "shell", "iptables", "-t", "nat", "-A", "OUTPUT", *rule(args))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "serial": args.serial,
                "deviceDns": args.device_dns,
                "hostGateway": args.host_gateway,
                "hostPort": args.host_port,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    status(args)


def remove(args: argparse.Namespace) -> None:
    ensure_root(args.serial)
    target = path(args)
    if not target.exists():
        raise RuntimeError(f"state file not found: {target}")
    state = json.loads(target.read_text(encoding="utf-8"))
    if state.get("serial") != args.serial:
        raise RuntimeError("state belongs to another ADB serial")
    while present(args):
        adb(args.serial, "shell", "iptables", "-t", "nat", "-D", "OUTPUT", *rule(args))
    target.unlink()
    status(args)


def status(args: argparse.Namespace) -> None:
    print(f"serial={args.serial}")
    print(f"dns_dnat={'present' if present(args) else 'absent'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove", "status"))
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--device-dns", default="10.0.2.3")
    parser.add_argument("--host-gateway", default="10.0.2.2")
    parser.add_argument("--host-port", type=int, default=18553)
    parser.add_argument("--state", type=Path, default=Path("/private/tmp/mahlkoenig-dns-bridge.json"))
    args = parser.parse_args(argv)
    if not 1 <= args.host_port <= 65535:
        parser.error("--host-port must be between 1 and 65535")
    try:
        {"install": install, "remove": remove, "status": status}[args.action](args)
    except (OSError, RuntimeError, subprocess.CalledProcessError, KeyError, ValueError) as exc:
        print(f"android DNS fixture bridge failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
