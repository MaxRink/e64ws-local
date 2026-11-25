"""Argparse entry point for ``python3 -m e64root`` and the ``e64root`` wrapper."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .commands import (
    cmd_api,
    cmd_esp,
    cmd_probe,
    cmd_revert,
    cmd_ssh,
    cmd_verify,
    cmd_web,
)
from .errors import E64RootError


def _target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", required=True, help="grinder hostname or IP, without a scheme")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument(
        "--scheme",
        choices=("https", "http"),
        default="https",
        help="web scheme; http requires --allow-http",
    )
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="permit the clear-text login injection on an isolated lab network",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="accept the image's self-signed TLS certificate (explicit opt-out)",
    )
    parser.add_argument("--ca-file", help="verify TLS against this CA/certificate file")
    parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="allow a globally routable target (otherwise private/link-local only)",
    )
    parser.add_argument(
        "--allow-unverified-target",
        action="store_true",
        help="continue even if the login page does not identify an E64/NG2",
    )


def _change_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--yes", action="store_true", help="confirm a device-changing action")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan without contacting the device",
    )


def _ssh_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ssh-key", help="owner private key for the system ssh client")
    parser.add_argument("--ssh-host", help="SSH host/forward, if different from --host")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH connect port (default: 22)")
    parser.add_argument(
        "--strict-host-key",
        action="store_true",
        help="use the normal known_hosts check instead of the disposable-key defaults",
    )
    parser.add_argument("--ssh-wait", type=float, default=60.0, help="seconds to wait for SSH")


def _api_options(parser: argparse.ArgumentParser) -> None:
    _target_options(parser)
    _ssh_options(parser)
    parser.add_argument(
        "--yes",
        action="store_true",
        help="execute the device-changing action (otherwise a dry run)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the script without contacting the device",
    )


def _web_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cmd", default="id", help="root command/shell fragment to run (default: id)")
    parser.add_argument("--command-timeout", type=int, default=20, help="remote watchdog seconds")
    parser.add_argument(
        "--callback-timeout",
        "--marker-timeout",
        dest="callback_timeout",
        type=float,
        default=60.0,
        help="seconds to wait for the output callback",
    )
    parser.add_argument(
        "--callback-host",
        help="LAN IP the grinder can reach (default: auto-detected local address)",
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=0,
        help="local callback port (default: choose a free port)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e64root",
        description=(
            "Owner-facing root/SSH installer for an E64 WS / NG2 grinder. "
            "Use only on a device you own. Every change needs --yes."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"e64root {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    probe = sub.add_parser(
        "probe",
        help="read-only fingerprint of HTTP/HTTPS, firmware, WSS, ESP, SSH and dev mode",
        allow_abbrev=False,
    )
    _target_options(probe)
    _ssh_options(probe)
    probe.add_argument("--json", action="store_true", help="machine-readable output")
    probe.add_argument("--http-port", type=int, default=80, help="plain HTTP port (default: 80)")
    probe.add_argument("--wss-port", type=int, default=9997, help="WSS port (default: 9997)")
    probe.add_argument(
        "--esp-request",
        action="store_true",
        help="also GET /upload_esp.php (rewrites /tmp/FirmwareUpdateState.json)",
    )
    probe.set_defaults(func=cmd_probe)

    web = sub.add_parser(
        "web",
        help="FW-01: run a root command through the login-form injection",
        allow_abbrev=False,
    )
    _target_options(web)
    _web_options(web)
    _change_options(web)
    web.set_defaults(func=cmd_web)

    esp = sub.add_parser(
        "esp",
        help="FW-02: run a root command through the unauthenticated ESP archive upload",
        allow_abbrev=False,
    )
    _target_options(esp)
    _web_options(esp)
    _ssh_options(esp)
    _change_options(esp)
    esp.add_argument(
        "--preflight",
        choices=("web", "ssh", "skip"),
        default="web",
        help="how to check /log, /dev/ttySTM5 and flashEspZip.sh before uploading",
    )
    esp.add_argument("--zip-out", help="also write the generated archive to this path")
    esp.set_defaults(func=cmd_esp)

    ssh = sub.add_parser(
        "ssh",
        help="install an owner key and a static dropbear (or enable an existing daemon)",
        allow_abbrev=False,
    )
    _target_options(ssh)
    _ssh_options(ssh)
    _change_options(ssh)
    ssh.add_argument("--via", choices=("web", "esp"), required=True, help="delivery path")
    ssh.add_argument("--pubkey-file", required=True, help="OpenSSH public key file to install")
    ssh.add_argument("--dropbear", help="static armhf dropbear binary (never downloaded)")
    ssh.add_argument(
        "--existing-daemon",
        help="absolute path to a dropbear/sshd already on the image (no upload)",
    )
    ssh.add_argument("--daemon-port", type=int, default=22, help="guest listen port (default: 22)")
    ssh.set_defaults(func=cmd_ssh)

    verify = sub.add_parser(
        "verify",
        help="prove uid 0 over SSH and list what persists",
        allow_abbrev=False,
    )
    _target_options(verify)
    _ssh_options(verify)
    verify.add_argument("--json", action="store_true", help="machine-readable output")
    verify.add_argument("--pubkey-file", help="also check these keys are present")
    verify.set_defaults(func=cmd_verify)

    revert = sub.add_parser(
        "revert",
        help="remove the key block, dropbear and init hook this tool added (dry-run by default)",
        allow_abbrev=False,
    )
    _target_options(revert)
    _ssh_options(revert)
    revert.add_argument("--yes", action="store_true", help="execute the revert (default is a dry run)")
    revert.add_argument("--pubkey-file", help="also remove exact key lines if no e64root block exists")
    revert.add_argument("--purge-backups", action="store_true", help="remove /root/.e64root as well")
    revert.add_argument("--keep-daemon", action="store_true", help="do not stop dropbear/sshd")
    revert.add_argument(
        "--print-script",
        "--show-script",
        dest="print_script",
        action="store_true",
        help="print the revert script instead of contacting the device",
    )
    revert.set_defaults(func=cmd_revert)

    api = sub.add_parser(
        "api",
        help="install, verify, or remove the local owner HTTP API module",
        allow_abbrev=False,
    )
    api_sub = api.add_subparsers(dest="api_subcommand", required=True)

    api_deploy = api_sub.add_parser(
        "deploy",
        help="install /usr/local/www/dev/rest_api_dev.php and /db/e64local/token",
        allow_abbrev=False,
    )
    _api_options(api_deploy)
    api_deploy.add_argument(
        "--token",
        help="owner token to write to /db/e64local/token (or use --generate-token)",
    )
    api_deploy.add_argument(
        "--generate-token",
        action="store_true",
        help="generate a random 256-bit hex owner token",
    )
    api_deploy.add_argument(
        "--enable-actions",
        action="store_true",
        help=(
            "write /db/e64local/actions.json, install the bounded action runner and "
            "the /etc/sudoers.d/e64local rule that lets www-data start it; without "
            "these files every action route fails closed with 403"
        ),
    )
    api_deploy.add_argument(
        "--enable-destructive-actions",
        action="store_true",
        help=(
            "also allow the destructive catalog (recipe delete, calibration, log clear, "
            "statistics reset, driver reset); requires --enable-actions and is off by default"
        ),
    )
    api_deploy.set_defaults(func=cmd_api)

    api_status = api_sub.add_parser(
        "status",
        help="read-only check: module, token file, and dev mode",
        allow_abbrev=False,
    )
    _api_options(api_status)
    api_status.set_defaults(func=cmd_api)

    api_revert = api_sub.add_parser(
        "revert",
        help="remove the API module, action gate and owner token (dry run without --yes)",
        allow_abbrev=False,
    )
    _api_options(api_revert)
    api_revert.add_argument(
        "--purge-audit",
        action="store_true",
        help="also delete /db/e64local/audit.jsonl and its rotations",
    )
    api_revert.set_defaults(func=cmd_api)

    return parser


def _validate(args: argparse.Namespace) -> None:
    if args.command in ("web", "esp", "ssh") and not args.dry_run:
        if not args.yes:
            raise E64RootError(
                f"'{args.command}' changes the device. Review the printed plan, then "
                "re-run with --yes (or use --dry-run)."
            )
    if getattr(args, "enable_destructive_actions", False) and not getattr(args, "enable_actions", False):
        raise E64RootError("--enable-destructive-actions requires --enable-actions")
    if args.command in ("web", "esp", "ssh") and not args.dry_run and args.scheme == "https":
        if not args.insecure and not args.ca_file:
            raise E64RootError(
                "the vendor certificate is self-signed: pass --insecure for this owner "
                "device, or --ca-file with the device certificate. TLS is verified by default."
            )


def dispatch(args: argparse.Namespace) -> int:
    _validate(args)
    return int(args.func(args))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return dispatch(args)
    except E64RootError as exc:
        print(f"e64root: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("e64root: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
