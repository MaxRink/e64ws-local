#!/usr/bin/env python3
"""CLI for the owner-controlled local E64 WS REST/WSS API."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .e64ws_api import E64LocalAPI, E64WSAPIError
    from .e64ws_protocol import HAZARDOUS_ACTIONS
except ImportError:  # direct ``python tools/e64ws_cli.py`` execution
    from e64ws_api import E64LocalAPI, E64WSAPIError
    from e64ws_protocol import HAZARDOUS_ACTIONS


def _json_arg(value: str | None) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid JSON: {exc}") from exc


def _emit(value: Any, output: str | None) -> None:
    if isinstance(value, bytes):
        if output:
            Path(output).write_bytes(value)
            print(output)
        else:
            sys.stdout.buffer.write(value)
        return
    json.dump(value, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="grinder hostname/IP, without a scheme")
    parser.add_argument("--token", help="existing WSS bearer token; never printed")
    parser.add_argument("--role", help="REST role used for local login")
    parser.add_argument("--password", help="prefer the hidden prompt to avoid shell history")
    parser.add_argument("--insecure", action="store_true", help="accept the image's self-signed TLS certificate")
    parser.add_argument("--ca-file", help="CA/certificate file for TLS verification")
    parser.add_argument("--scheme", choices=("wss", "ws"), default="wss", help="use ws only for the loopback simulator")
    parser.add_argument("--port", type=int, default=9997)
    parser.add_argument("--rest-port", type=int, help="REST/HTTP port; defaults to 443 for wss or 80 for ws")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output", help="write binary REST downloads to this path")
    sub = parser.add_subparsers(dest="operation", required=True)
    rest = sub.add_parser("rest", help="call a recovered REST route")
    rest.add_argument("route")
    rest.add_argument("--data", type=_json_arg)
    ws = sub.add_parser("ws", help="call a recovered local WebSocket command")
    ws_group = ws.add_mutually_exclusive_group(required=True)
    ws_group.add_argument("--request")
    ws_group.add_argument("--action")
    ws.add_argument("--data", type=_json_arg)
    ws.add_argument("--action-type")
    ws.add_argument("--allow-hazardous", action="store_true")
    sub.add_parser("state", help="RequestDriverState")
    sub.add_parser("config", help="RequestDriverConfig")
    sub.add_parser("gbs-report", help="GbsCreateReport")
    sub.add_parser("ping")
    sub.add_parser("machine-info")
    sub.add_parser("wifi-info")
    sub.add_parser("scan-wifi")
    sub.add_parser("update-session")
    sub.add_parser("logout")
    reboot = sub.add_parser("reboot")
    reboot.add_argument("--allow-hazardous", action="store_true")
    sub.add_parser("firmware-state")
    onboard = sub.add_parser("onboarding")
    onboard.add_argument("--data", type=_json_arg, required=True)
    download_db = sub.add_parser("download-database")
    download_db.add_argument(
        "--output", default=argparse.SUPPRESS,
        help="write the binary database to this path",
    )
    download_logs = sub.add_parser("download-logs")
    download_logs.add_argument(
        "--output", default=argparse.SUPPRESS,
        help="write the binary log archive to this path",
    )

    args = parser.parse_args(argv)
    if args.insecure and args.ca_file:
        parser.error("choose --insecure or --ca-file, not both")
    if args.operation == "ws" and args.request and args.request.startswith("GrinderAction"):
        parser.error("use --action for GrinderAction commands so the hazardous-operation guard is applied")
    if args.operation == "ws" and args.action and args.action in HAZARDOUS_ACTIONS and not args.allow_hazardous:
        parser.error("physical/maintenance action is guarded; add --allow-hazardous on an isolated test machine")
    if args.operation == "reboot" and not args.allow_hazardous:
        parser.error("reboot is guarded; add --allow-hazardous on an isolated test machine")

    api = E64LocalAPI(
        args.host,
        insecure=args.insecure,
        ca_file=args.ca_file,
        token=args.token,
        timeout=args.timeout,
        scheme=args.scheme,
        port=args.port,
        rest_port=args.rest_port,
    )
    try:
        rest_session_operations = {
            "onboarding", "download-database", "download-logs", "reboot",
            "firmware-state", "machine-info", "wifi-info", "scan-wifi",
            "update-session", "logout",
        }
        wss_operations = {"state", "config", "gbs-report", "ws"}
        if args.operation in rest_session_operations and not args.role:
            parser.error(
                "REST operations need --role/--password; a WSS --token does not create a PHP cookie session"
            )
        needs_login = (
            args.operation in rest_session_operations
            or (args.operation == "rest" and bool(args.role))
            or (args.operation in wss_operations and not args.token)
        )
        if needs_login:
            if not args.role:
                parser.error("this operation needs a REST session; provide --role and --password, or --token for WSS")
            password = args.password if args.password is not None else getpass.getpass("local grinder password: ")
            api.login(args.role, password)

        if args.operation == "rest":
            value = api.rest(args.route, args.data)
        elif args.operation == "ws":
            if not api.token:
                parser.error("ws needs --token or --role/--password")
            value = api.ws_action(args.action, args.data, action_type=args.action_type, allow_hazardous=args.allow_hazardous) if args.action else api.ws_request(args.request, args.data)
        elif args.operation == "state":
            value = api.driver_state()
        elif args.operation == "config":
            value = api.driver_config()
        elif args.operation == "gbs-report":
            value = api.gbs_report()
        elif args.operation == "ping":
            value = api.ping()
        elif args.operation == "machine-info":
            value = api.machine_info()
        elif args.operation == "wifi-info":
            value = api.wifi_info()
        elif args.operation == "scan-wifi":
            value = api.scan_wifi()
        elif args.operation == "update-session":
            value = api.update_session()
        elif args.operation == "logout":
            value = api.logout()
        elif args.operation == "reboot":
            value = api.reboot(allow_hazardous=args.allow_hazardous)
        elif args.operation == "firmware-state":
            value = api.firmware_update_state()
        elif args.operation == "onboarding":
            value = api.request_onboarding(args.data)
        elif args.operation == "download-database":
            value = api.download_database()
        elif args.operation == "download-logs":
            value = api.download_machine_logs()
        else:  # pragma: no cover - argparse prevents this
            parser.error("unknown operation")
        _emit(value, args.output if args.operation in {"download-database", "download-logs"} else None)
        return 0
    except E64WSAPIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())
