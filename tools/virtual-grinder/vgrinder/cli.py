"""`vg` command line interface for the virtual grinder."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from . import paths, proto

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_RUNNING = 2


# ------------------------------------------------------------------ client


def send(cmd: str, args: dict | None = None, timeout: float = 180.0) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(paths.DAEMON_SOCK))
        sock.sendall((json.dumps({"cmd": cmd, "args": args or {}}) + "\n").encode())
        buf = bytearray()
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
        if not buf:
            return {"ok": False, "error": "empty reply from daemon"}
        return json.loads(bytes(buf).split(b"\n", 1)[0])
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc), "daemon_down": True}
    finally:
        sock.close()


def daemon_alive() -> bool:
    return send("ping", timeout=2).get("ok", False)


def require_daemon() -> dict | None:
    result = send("ping", timeout=2)
    if result.get("ok"):
        return None
    print("vg: daemon is not running (start it with `vg up`)", file=sys.stderr)
    return result


# ------------------------------------------------------------------ output


def print_json(value) -> None:
    print(json.dumps(value, indent=2, default=str))


def print_status(status: dict) -> None:
    vm = status.get("vm", {})
    services = status.get("services", {})
    guest = status.get("guest", {})
    esp = status.get("esp", {})
    grinder = status.get("grinder", {})
    print(f"VM        running={vm.get('running')} boot={vm.get('boot')} "
          f"pid={vm.get('pid')} uptime={vm.get('uptime_s')}s")
    qmp = vm.get("qmp", {})
    if qmp.get("ok"):
        print(f"QMP       {qmp.get('status', {}).get('status')}")
    else:
        print(f"QMP       down ({qmp.get('error')})")
    print(f"HTTP      {services.get('http')}")
    print(f"HTTPS     {services.get('https')}")
    print(f"WSS       {services.get('wss')}")
    print(f"Qt VNC    {services.get('qt_vnc')}")
    print(f"Agent     connected={guest.get('ok')} keys={guest.get('keys')} "
          f"weight={guest.get('weight_g')}g")
    print(f"ESP       mode={esp.get('mode')} connected={esp.get('connected')} "
          f"ssid={esp.get('ssid')!r} rx={esp.get('frames_rx')} tx={esp.get('frames_tx')}")
    print(f"Grinder   weight={grinder.get('weight_g')}g last={grinder.get('last_action')}")
    screen = (grinder.get("last_screen") or {}).get("path")
    if screen:
        print(f"Screen    {screen}")


# ------------------------------------------------------------------- start


def cmd_build(args) -> int:
    from .build import build_all
    try:
        artifacts = build_all(force=args.force)
    except SystemExit as exc:
        print(f"vg build: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print("artifacts:")
    for name, path in artifacts.items():
        print(f"  {name:8s} {path}")
    return EXIT_OK


def cmd_up(args) -> int:
    if daemon_alive():
        print("vg: already running")
        result = send("status")
        print_status(result)
        return EXIT_OK
    paths.ensure_dirs()
    from .build import build_all
    try:
        build_all(force=False)
    except SystemExit as exc:
        print(f"vg: {exc}", file=sys.stderr)
        return EXIT_ERROR

    log_path = paths.WORK / "daemon.out"
    log = open(log_path, "ab")
    command = [sys.executable, "-m", "vgrinder.daemon", "--no-wait",
               "--control-port", str(args.control_port)]
    if args.no_scale:
        command.append("--no-scale")
    # The daemon imports `vgrinder`, which normally lives under VG_ROOT when the
    # tool tree has been staged there. Running the checked-out `vg` against a
    # bare VG_ROOT means the package is next to this file instead, so expose
    # both roots rather than requiring a copy of the tree.
    package_root = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        entry
        for entry in (str(paths.ROOT), package_root, env.get("PYTHONPATH", ""))
        if entry
    )
    process = subprocess.Popen(command, cwd=str(paths.ROOT), stdout=log, stderr=log,
                               stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    deadline = time.time() + 25
    while time.time() < deadline:
        if daemon_alive():
            break
        if process.poll() is not None:
            print(f"vg: daemon exited; see {log_path}", file=sys.stderr)
            return EXIT_ERROR
        time.sleep(0.4)
    else:
        print(f"vg: daemon did not answer on {paths.DAEMON_SOCK}", file=sys.stderr)
        return EXIT_ERROR

    if args.no_wait:
        print(f"vg: daemon started (pid {process.pid}), boot continues in the background")
        print(f"    control: http://127.0.0.1:{args.control_port}/  logs: {paths.SERIAL_LOG}")
        return EXIT_OK

    timeout = float(os.environ.get("VG_BOOT_TIMEOUT", "150"))
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        # status probes HTTP/HTTPS/WSS/VNC; on a booting guest each probe can
        # run into its own timeout, so this request needs more than 10 s.
        status = send("status", timeout=40)
        boot = (status.get("vm") or {}).get("boot")
        if boot != last:
            print(f"  boot: {boot}")
            last = boot
        if boot in ("login", "hmi-start"):
            break
        if not (status.get("vm") or {}).get("running", False):
            print("vg: QEMU exited during boot; see " + str(paths.SERIAL_LOG), file=sys.stderr)
            return EXIT_ERROR
        time.sleep(2)
    print()
    print_status(send("status", timeout=10))
    print()
    print(f"web UI   http://127.0.0.1:{paths.DEFAULTS['http_port']}/login.php")
    print(f"HTTPS    https://127.0.0.1:{paths.DEFAULTS['https_port']}/login.php")
    print(f"HMI VNC  vnc://127.0.0.1:{paths.DEFAULTS['qt_vnc_port']}")
    print(f"logs     vg logs -f")
    return EXIT_OK


def cmd_down(args) -> int:
    result = send("shutdown", timeout=20)
    if not result.get("ok"):
        print("vg: daemon is not running")
        return EXIT_OK
    deadline = time.time() + 20
    while time.time() < deadline and paths.DAEMON_SOCK.exists():
        time.sleep(0.5)
    print("vg: stopped")
    return EXIT_OK


def cmd_status(args) -> int:
    result = send("status")
    if args.json:
        print_json(result)
        return EXIT_OK if result.get("ok") else EXIT_NOT_RUNNING
    if not result.get("ok"):
        print("vg: daemon is not running (start it with `vg up`)")
        if paths.STATE_FILE.exists():
            print(f"last state: {paths.STATE_FILE}")
        return EXIT_NOT_RUNNING
    print_status(result)
    return EXIT_OK


def cmd_state(args) -> int:
    result = send("state")
    print_json(result)
    return EXIT_OK if result.get("ok") else EXIT_NOT_RUNNING


def cmd_issue(args) -> int:
    result = send("issue", {"mode": args.mode})
    print_json(result) if args.json else print(result.get("error") or f"issue mode {args.mode}")
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_hardware(args) -> int:
    updates = {}
    if args.dd_um is not None:
        updates["dd_um"] = args.dd_um
    if args.agsa_current is not None:
        updates["agsa_current_ma"] = args.agsa_current
    if args.ntc1 is not None:
        updates["ntc1_c"] = args.ntc1
    if args.ntc2 is not None:
        updates["ntc2_c"] = args.ntc2
    if args.fan_rpm is not None:
        updates["fan1_rpm"] = args.fan_rpm
        updates["fan2_rpm"] = args.fan_rpm
    result = send("hardware", updates)
    print_json(result)
    return EXIT_OK if result.get("ok") else EXIT_NOT_RUNNING


def cmd_logs(args) -> int:
    path = paths.SERIAL_LOG
    if not path.exists():
        print(f"vg: no log at {path}; start the VM with `vg up`", file=sys.stderr)
        return EXIT_ERROR
    with path.open("r", errors="replace") as handle:
        lines = handle.readlines()
        for line in lines[-args.lines:]:
            sys.stdout.write(line)
        if not args.follow:
            return EXIT_OK
        sys.stdout.flush()
        while True:
            line = handle.readline()
            if line:
                sys.stdout.write(line)
                sys.stdout.flush()
            else:
                time.sleep(0.4)


# ------------------------------------------------------------------ inputs


def cmd_key(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("key", {"name": args.name, "index": args.index,
                          "hold_ms": args.hold, "value": args.value})
    if args.json:
        print_json(result)
    else:
        print(result.get("error") or f"key {args.name or args.index}: {result}")
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_rotate(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("rotate", {"clicks": args.clicks})
    print_json(result) if args.json else print(result.get("error") or f"rotated {args.clicks}")
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_weight(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    if args.base is not None:
        result = send("weight.base", {"grams": args.base})
    elif args.rate is not None:
        result = send("weight.rate", {"grams_per_s": args.rate})
    elif args.start:
        result = send("weight.start", {})
    elif args.stop:
        result = send("weight.stop", {})
    elif args.grams is not None:
        result = send("weight", {"grams": args.grams})
    else:
        result = {"ok": False, "error": "give grams, --base, --rate, --start or --stop"}
    if args.json:
        print_json(result)
    else:
        print(result.get("error") or result)
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_wifi(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    if args.action == "scan":
        result = send("wifi_scan", {})
        if args.json:
            print_json(result)
        else:
            for ap in result.get("scan", []):
                print(f"{ap['ssid']:24s} ch{ap['channel']:<3d} {ap['rssi']:>4d} dBm  {ap['bssid']}")
    elif args.action == "join":
        result = send("wifi_join", {"ssid": args.ssid, "password": args.password or ""})
        print_json(result) if args.json else print(
            result.get("error") or f"ESP state: connected={result.get('esp', {}).get('connected')} "
            f"ssid={result.get('esp', {}).get('ssid')!r}")
    elif args.action == "off":
        result = send("wifi_off")
        print_json(result) if args.json else print("WiFi disconnected (ESP state)")
    else:
        result = send("wifi_status")
        esp = result.get("esp", {})
        print(f"mode={esp.get('mode')} connected={esp.get('connected')} ssid={esp.get('ssid')!r} "
              f"ip={esp.get('ip', '-')}")
        if args.json:
            print_json(result)
    return EXIT_OK


def cmd_grind(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    if args.action == "stop":
        result = send("grind_stop")
    else:
        result = send("grind_start", {"mode": args.mode, "target_g": args.target})
    if args.json:
        print_json(result)
    else:
        print(result.get("error") or json.dumps(result.get("reply", result), indent=1))
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_esp(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    if args.action == "event":
        result = send("esp_event", {"id": args.id, "data_hex": args.data or ""})
    else:
        result = send("esp_raw", {"hex": args.hex})
    print_json(result)
    return EXIT_OK if result.get("ok") else EXIT_ERROR


# ----------------------------------------------------------------- outputs


def cmd_screen(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("screen", {"display": args.display, "path": args.path,
                             "timeout": args.timeout})
    if result.get("ok"):
        print(f"{result['path']} ({result['width']}x{result['height']}, "
              f"{result['bytes']} bytes)")
    else:
        print(f"vg: capture failed: {result.get('error')}", file=sys.stderr)
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_web(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("web_get", {"path": args.path, "https": not args.http})
    if args.json:
        print_json(result)
    else:
        print(f"{result.get('url')} -> {result.get('status')} {result.get('reason', '')}")
        if result.get("title"):
            print(f"title: {result['title']}")
        if args.body:
            print(result.get("body", ""))
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_wss(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    if args.json_message:
        message = json.loads(args.json_message)
    else:
        message = {"type": args.type, "msgId": args.msg_id}
        data = json.loads(args.data) if args.data else None
        if data is not None:
            message["data"] = data
    result = send("wss", {"message": message, "token": args.token,
                          "mint": not args.no_mint, "timeout": args.timeout})
    print_json(result)
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_shell(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("shell", {"cmd": " ".join(args.command)}, timeout=30)
    if result.get("ok"):
        sys.stdout.write(result.get("stdout", ""))
        return EXIT_OK
    print(result.get("error"), file=sys.stderr)
    return EXIT_ERROR


def cmd_vnc(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    if args.action == "click":
        result = send("vnc", {"action": "click", "x": args.x, "y": args.y})
    else:
        result = send("vnc", {"action": "key", "keysym": int(args.keysym, 0)})
    print_json(result)
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_power(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("power", {"action": args.action})
    print_json(result)
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def cmd_probe(args) -> int:
    if require_daemon():
        return EXIT_NOT_RUNNING
    result = send("probe")
    print_json(result)
    return EXIT_OK


# ----------------------------------------------------------------- selftest


def cmd_selftest(args) -> int:
    problems = proto.selftest()
    print("protocol vectors: " + ("OK" if not problems else f"FAIL {problems}"))
    checks = {
        "agent binary": paths.GUEST / "build/vg-agent",
        "shim": paths.GUEST / "build/libvgsim.so",
        "kernel": paths.KERNEL,
        "initrd": paths.INITRD,
        "dtb": paths.DTB,
        "rootfs": paths.ROOTFS_IMG,
        "app": paths.APP_IMG,
        "db": paths.DB_IMG,
    }
    missing = 0
    for name, path in checks.items():
        state = "ok" if path.exists() else "missing"
        if not path.exists():
            missing += 1
        print(f"  {name:12s} {state:8s} {path}")
    if missing:
        print(f"{missing} artifact(s) missing; run `vg build`")
        return EXIT_ERROR
    if not problems:
        print("selftest: OK")
    return EXIT_OK if not problems else EXIT_ERROR


# --------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vg", description="E64 WS virtual grinder")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("build", help="build the VM images")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("up", help="start the VM and control daemon")
    p.add_argument("--no-wait", action="store_true", help="return before the guest boots")
    p.add_argument("--no-scale", action="store_true", help="do not start the OpenScale fixture")
    p.add_argument("--control-port", type=int, default=paths.DEFAULTS["control_port"])
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("down", help="stop the VM and daemon")
    p.set_defaults(func=cmd_down)

    p = sub.add_parser("status", help="VM, service and guest status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("state", help="full state as JSON")
    p.set_defaults(func=cmd_state)

    p = sub.add_parser("issue", help="switch /etc/issue development|custom (REST vs WSS dev mode)")
    p.add_argument("mode", choices=("development", "custom"))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("hardware", help="synthetic hardware model (load cell, DD/AGSA, NTC, fan)")
    p.add_argument("--dd-um", type=int)
    p.add_argument("--agsa-current", type=int, help="AGSA current in mA")
    p.add_argument("--ntc1", type=float)
    p.add_argument("--ntc2", type=float)
    p.add_argument("--fan-rpm", type=int)
    p.set_defaults(func=cmd_hardware)

    p = sub.add_parser("logs", help="serial console log")
    p.add_argument("-n", "--lines", type=int, default=120)
    p.add_argument("-f", "--follow", action="store_true")
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("key", help="press or hold a front-panel key")
    p.add_argument("name", nargs="?", help="top|bottom|rotary|ddd|hopper|agsa")
    p.add_argument("--index", type=int)
    p.add_argument("--hold", type=int, default=150, help="hold time in ms")
    p.add_argument("--value", type=int, choices=(0, 1), help="set level instead of pulsing")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_key)

    p = sub.add_parser("press", help="alias for key")
    p.add_argument("name", nargs="?")
    p.add_argument("--index", type=int)
    p.add_argument("--hold", type=int, default=150)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_key, value=None)

    p = sub.add_parser("rotate", help="turn the rotary encoder")
    p.add_argument("clicks", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rotate)

    p = sub.add_parser("weight", help="load-cell simulation: absolute, tare, rate or ramp")
    p.add_argument("grams", type=float, nargs="?")
    p.add_argument("--base", type=float, help="empty-basket tare in grams")
    p.add_argument("--rate", type=float, help="grind rate in grams/second")
    p.add_argument("--start", action="store_true", help="start the weight ramp")
    p.add_argument("--stop", action="store_true", help="stop the weight ramp")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_weight)

    p = sub.add_parser("wifi", help="virtual ESP32 WiFi state")
    p.add_argument("action", choices=("scan", "join", "off", "status"))
    p.add_argument("ssid", nargs="?")
    p.add_argument("--password", default="")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_wifi)

    p = sub.add_parser("grind", help="send a GrinderAction over WSS")
    p.add_argument("action", choices=("start", "stop"))
    p.add_argument("--mode", choices=("manual", "gbw", "gbt"), default="manual")
    p.add_argument("--target", type=float, help="target weight in grams (GBW)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_grind)

    p = sub.add_parser("esp", help="inject ESP frames/events")
    esp_sub = p.add_subparsers(dest="action", required=True)
    pe = esp_sub.add_parser("raw", help="write a raw frame to the guest")
    pe.add_argument("hex")
    pe = esp_sub.add_parser("event", help="send an async event")
    pe.add_argument("id", type=int)
    pe.add_argument("--data", default="")
    p.set_defaults(func=cmd_esp)

    p = sub.add_parser("screen", help="capture the HMI display over VNC")
    p.add_argument("path", nargs="?")
    p.add_argument("--display", choices=("qt", "qemu"), default="qt")
    p.add_argument("--timeout", type=float, default=20.0)
    p.set_defaults(func=cmd_screen)

    p = sub.add_parser("web", help="query the vendor HTTP(S) UI")
    web_sub = p.add_subparsers(dest="action", required=True)
    pw = web_sub.add_parser("get")
    pw.add_argument("path", nargs="?", default="/login.php")
    pw.add_argument("--http", action="store_true")
    pw.add_argument("--body", action="store_true")
    pw.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_web)

    p = sub.add_parser("wss", help="send a JSON frame to the HMI WebSocket server")
    p.add_argument("type", nargs="?")
    p.add_argument("--data", help="data object as JSON")
    p.add_argument("--json-message", help="complete message as JSON")
    p.add_argument("--msg-id", type=int, default=1)
    p.add_argument("--token")
    p.add_argument("--no-mint", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.set_defaults(func=cmd_wss)

    p = sub.add_parser("shell", help="run a command in the guest")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("vnc", help="inject pointer/key events into the Qt VNC display")
    vnc_sub = p.add_subparsers(dest="action", required=True)
    pv = vnc_sub.add_parser("click")
    pv.add_argument("x", type=int)
    pv.add_argument("y", type=int)
    pv = vnc_sub.add_parser("key")
    pv.add_argument("keysym", help="X11 keysym, e.g. 0x34 for '4' or 0xff0d for Return")
    p.set_defaults(func=cmd_vnc)

    p = sub.add_parser("power", help="reboot or power off")
    p.add_argument("action", choices=("reset", "off", "reboot", "shutdown"))
    p.set_defaults(func=cmd_power)

    p = sub.add_parser("probe", help="probe every observable service")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("selftest", help="check protocol vectors and artifacts")
    p.set_defaults(func=cmd_selftest)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
