#!/usr/bin/env python3
"""Install/remove an exact cloud-host override on a rootable Android AVD.

The official APK uses ``sync.mahlkoenig.com`` on HTTPS port 443.  This helper
maps only that hostname to the emulator loopback when possible, or installs
destination-specific DNAT rules for explicitly supplied resolved addresses on
immutable AVD images. It stores the original ``/etc/hosts`` text when
applicable and removes every exact NAT rule on cleanup.

Use only on a disposable, owner-controlled emulator.  This does not alter a
physical grinder, router, DNS server, or the host's networking.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path


MARKER = "# mahlkoenig-local-cloud-fixture"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def adb(serial: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["adb", "-s", serial, *args], check=check)


def root(serial: str) -> None:
    result = adb(serial, "root", check=False)
    combined = (result.stdout + result.stderr).lower()
    if result.returncode != 0 or "cannot run as root" in combined:
        raise RuntimeError("selected target is not a rootable Android emulator")
    adb(serial, "wait-for-device")
    if "uid=0(root)" not in adb(serial, "shell", "id").stdout:
        raise RuntimeError("adbd did not become root")


def read_hosts(serial: str) -> str:
    result = adb(serial, "shell", "cat", "/etc/hosts")
    return result.stdout


def write_hosts(serial: str, content: str) -> None:
    encoded = base64.b64encode(content.encode()).decode()
    adb(serial, "shell", "sh", "-c", f"echo {encoded} | base64 -d > /etc/hosts")


def nat_rule(address: str, args: argparse.Namespace) -> list[str]:
    return [
        "-d", f"{address}/32", "-p", "tcp", "--dport", str(args.device_port),
        "-j", "DNAT", "--to-destination", f"{args.host_gateway}:{args.host_port}",
    ]


def has_nat_rule(serial: str, rule_args: list[str]) -> bool:
    return adb(
        serial, "shell", "iptables", "-t", "nat", "-C", "OUTPUT", *rule_args,
        check=False,
    ).returncode == 0


def state_path(args: argparse.Namespace) -> Path:
    return args.state.expanduser().resolve()


def install(args: argparse.Namespace) -> None:
    root(args.serial)
    target = state_path(args)
    if target.exists():
        raise RuntimeError(f"state file already exists; remove first: {target}")
    original: str | None = None
    if not args.resolved_address:
        original = read_hosts(args.serial)
        line = f"127.0.0.1 {args.cloud_host} {MARKER}"
        updated = original.rstrip("\n") + "\n" + line + "\n"
        write_hosts(args.serial, updated)
        try:
            adb(args.serial, "reverse", f"tcp:{args.device_port}", f"tcp:{args.host_port}")
        except Exception:
            write_hosts(args.serial, original)
            raise
    else:
        for address in args.resolved_address:
            rule_args = nat_rule(address, args)
            if not has_nat_rule(args.serial, rule_args):
                adb(args.serial, "shell", "iptables", "-t", "nat", "-A", "OUTPUT", *rule_args)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "serial": args.serial,
                "cloudHost": args.cloud_host,
                "devicePort": args.device_port,
                "hostPort": args.host_port,
                "originalHostsBase64": (
                    base64.b64encode(original.encode()).decode() if original is not None else None
                ),
                "resolvedAddresses": args.resolved_address,
                "hostGateway": args.host_gateway,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    status(args)


def remove(args: argparse.Namespace) -> None:
    root(args.serial)
    target = state_path(args)
    if not target.exists():
        raise RuntimeError(f"state file not found: {target}")
    state = json.loads(target.read_text(encoding="utf-8"))
    if state.get("serial") != args.serial:
        raise RuntimeError("state file belongs to a different ADB serial")
    if state.get("originalHostsBase64"):
        original = base64.b64decode(state["originalHostsBase64"]).decode()
        write_hosts(args.serial, original)
        adb(args.serial, "reverse", "--remove", f"tcp:{state['devicePort']}", check=False)
    else:
        for address in state.get("resolvedAddresses", []):
            rule_args = [
                "-d", f"{address}/32", "-p", "tcp", "--dport", str(state["devicePort"]),
                "-j", "DNAT", "--to-destination", f"{state['hostGateway']}:{state['hostPort']}",
            ]
            while has_nat_rule(args.serial, rule_args):
                adb(args.serial, "shell", "iptables", "-t", "nat", "-D", "OUTPUT", *rule_args)
        args.resolved_address = list(state.get("resolvedAddresses", []))
        args.host_gateway = state.get("hostGateway", args.host_gateway)
    target.unlink()
    status(args)


def status(args: argparse.Namespace) -> None:
    hosts = read_hosts(args.serial)
    mappings = adb(args.serial, "reverse", "--list", check=False).stdout
    print(f"serial={args.serial}")
    print(f"hosts_marker={'present' if MARKER in hosts else 'absent'}")
    if args.resolved_address:
        for address in args.resolved_address:
            print(
                f"dnat_{address}_{args.device_port}="
                + ("present" if has_nat_rule(args.serial, nat_rule(address, args)) else "absent")
            )
    else:
        print(
            f"reverse_tcp_{args.device_port}="
            + ("present" if f"tcp:{args.device_port} tcp:{args.host_port}" in mappings else "absent")
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove", "status"))
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--cloud-host", default="sync.mahlkoenig.com")
    parser.add_argument("--device-port", type=int, default=443)
    parser.add_argument("--host-port", type=int, default=8444)
    parser.add_argument(
        "--resolved-address",
        action="append",
        default=[],
        help="Resolved cloud A/AAAA address for immutable AVDs; repeat for each address",
    )
    parser.add_argument("--host-gateway", default="10.0.2.2")
    parser.add_argument("--state", type=Path, default=Path("/private/tmp/mahlkoenig-cloud-bridge.json"))
    args = parser.parse_args(argv)
    for port in (args.device_port, args.host_port):
        if not 1 <= port <= 65535:
            parser.error("ports must be between 1 and 65535")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        {"install": install, "remove": remove, "status": status}[args.action](args)
    except (OSError, RuntimeError, subprocess.CalledProcessError, KeyError, ValueError) as exc:
        print(f"android cloud fixture bridge failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
