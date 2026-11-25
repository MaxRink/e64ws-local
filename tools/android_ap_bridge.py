#!/usr/bin/env python3
"""Route official-app grinder AP addresses to the owner-local simulator.

This tool changes only a selected Android emulator.  It requires a rootable
AVD because the official APK contains fixed provisioning-address candidates
(`192.168.4.1` and `172.16.0.1`) that `adb reverse` alone cannot rewrite.

The installed path is:

    APK -> AP_ADDRESS:80 -> emulator DNAT -> 127.0.0.1:HOST_PORT
        -> adb reverse -> host 127.0.0.1:HOST_PORT

Use ``remove`` after a test.  Rules are exact and idempotent; unrelated
iptables and reverse mappings are not changed.
"""

from __future__ import annotations

import argparse
import subprocess
import sys


DEFAULT_ADDRESSES = ("192.168.4.1", "172.16.0.1")


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def adb(serial: str, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["adb", "-s", serial, *arguments], check=check)


def rule(address: str, device_port: int, host_port: int) -> list[str]:
    return [
        "-d", f"{address}/32", "-p", "tcp", "--dport", str(device_port),
        "-j", "DNAT", "--to-destination",
        f"127.0.0.1:{host_port}",
    ]


def ensure_root(serial: str) -> None:
    result = adb(serial, "root", check=False)
    combined = (result.stdout + result.stderr).lower()
    if result.returncode != 0 or "cannot run as root" in combined:
        raise RuntimeError("selected Android target is not a rootable emulator")
    adb(serial, "wait-for-device")
    identity = adb(serial, "shell", "id").stdout
    if "uid=0(root)" not in identity:
        raise RuntimeError(f"adbd did not become root: {identity.strip()}")


def has_rule(serial: str, arguments: list[str]) -> bool:
    return adb(
        serial, "shell", "iptables", "-t", "nat", "-C", "OUTPUT",
        *arguments, check=False,
    ).returncode == 0


def install(args: argparse.Namespace) -> None:
    ensure_root(args.serial)
    adb(args.serial, "reverse", f"tcp:{args.host_port}", f"tcp:{args.host_port}")
    for address in args.address:
        arguments = rule(address, args.device_port, args.host_port)
        if not has_rule(args.serial, arguments):
            adb(args.serial, "shell", "iptables", "-t", "nat", "-A", "OUTPUT", *arguments)
    status(args)


def remove(args: argparse.Namespace) -> None:
    ensure_root(args.serial)
    for address in args.address:
        arguments = rule(address, args.device_port, args.host_port)
        while has_rule(args.serial, arguments):
            adb(args.serial, "shell", "iptables", "-t", "nat", "-D", "OUTPUT", *arguments)
    adb(args.serial, "reverse", "--remove", f"tcp:{args.host_port}", check=False)
    status(args)


def status(args: argparse.Namespace) -> None:
    mappings = adb(args.serial, "reverse", "--list", check=False).stdout
    reverse_present = f"tcp:{args.host_port} tcp:{args.host_port}" in mappings
    print(f"serial={args.serial}")
    print(f"reverse_tcp_{args.host_port}={'present' if reverse_present else 'absent'}")
    for address in args.address:
        arguments = rule(address, args.device_port, args.host_port)
        installed = has_rule(args.serial, arguments)
        print(f"dnat_{address}_{args.device_port}={'present' if installed else 'absent'}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove", "status"))
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--host-port", type=int, default=8787)
    parser.add_argument("--device-port", type=int, default=80)
    parser.add_argument("--address", action="append", default=[])
    args = parser.parse_args(argv)
    if not args.address:
        args.address = list(DEFAULT_ADDRESSES)
    for port in (args.host_port, args.device_port):
        if not 1 <= port <= 65535:
            parser.error("ports must be between 1 and 65535")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        {"install": install, "remove": remove, "status": status}[args.action](args)
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"android AP bridge failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
