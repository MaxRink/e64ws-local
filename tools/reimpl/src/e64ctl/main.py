"""Service entry point: WSS :9997 + REST :8080 + ESP bridge.

Run it instead of ``NgxUiApp`` in the virtual grinder, or standalone on a host:

    python -m e64ctl --state-dir /tmp/e64-run --dev-mode
    python -m e64ctl --wss-port 9997 --http-port 8080 --esp-device /dev/esps0
"""
from __future__ import annotations

import argparse
import os
import signal
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from . import jsonfmt
from .control import ControlServer, ControlState
from .dispatch import Dispatcher
from .esp_bridge import EspBridge
from .handlers import Handlers
from .persistence import Persistence
from .registry import COMMANDS
from .rest import RedirectServer, RestContext, RestServer
from .state import DeviceState, MachineInfo
from .tokens import TokenStore
from .wss import WssServer
from .live_profile import apply_live_hsg_profile
from .weight_trace import (apply_capture_snapshot, load_capture_snapshot,
                           load_capture_trace)


@dataclass
class ServiceConfig:
    state_dir: str = "/tmp/e64ctl"
    wss_port: int = 9997
    http_port: int = 8080
    https_port: Optional[int] = None
    bind: str = "127.0.0.1"
    dev_mode: Optional[bool] = None          # None -> probe /etc/issue
    issue_file: str = "/etc/issue"
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    esp_device: Optional[str] = None
    esp_json_device: Optional[str] = None
    simulate_esp: bool = True
    serial: str = "000000"
    grinder_type: int = 0
    grinder_type_name: str = "E64 WS"
    tick_interval: float = 0.1
    control_socket: Optional[str] = None
    motion_sim: bool = True
    live_profile: bool = False
    weight_trace: Optional[str] = None
    debug: bool = False


def probe_dev_mode(issue_file: str) -> bool:
    """``RootfsVersionReader::isDevVersion`` (ELF 0x00233b08).

    Exactly 14 space-separated tokens and token[0] == "development"
    (case-insensitive); a substring match anywhere else does not count.
    """
    try:
        with open(issue_file, "r", encoding="utf-8", errors="replace") as handle:
            line = handle.readline().rstrip("\n")
    except OSError:
        return False
    tokens = line.split(" ")
    tokens = [token for token in tokens if token]
    if len(tokens) != 14:
        return False
    return tokens[0].lower() == "development"


class Service:
    def __init__(self, config: ServiceConfig, clock=time.time) -> None:
        self.config = config
        self.clock = clock
        self.dev_mode = (config.dev_mode if config.dev_mode is not None
                         else probe_dev_mode(config.issue_file))
        self.persistence = Persistence(config.state_dir, clock)
        self.tokens = TokenStore(os.path.join(config.state_dir, "tmp"), clock)
        self.state = DeviceState(clock=clock)
        self.state.motion_simulated = config.motion_sim
        self.state.machine = MachineInfo(
            grinder_type=config.grinder_type,
            grinder_type_name=config.grinder_type_name,
            serial_number=config.serial,
            hostname=f"hemro_hsg_{config.serial}",
        )
        if config.live_profile:
            apply_live_hsg_profile(self.state)
        if config.weight_trace:
            apply_capture_snapshot(self.state,
                                   load_capture_snapshot(config.weight_trace))
            self.state.grind.weight_trace = load_capture_trace(
                config.weight_trace,
                baseline_gr=self.state.grind.current_weight_gr)
        self._load_persisted_settings()
        self.esp = EspBridge(device=config.esp_device,
                             json_device=config.esp_json_device,
                             simulate=config.simulate_esp, state=self.state)
        self.handlers = Handlers(self.state, self.persistence, self.esp,
                                 dev_mode=lambda: self.dev_mode)
        self.dispatcher = Dispatcher(
            self.handlers, self.tokens, lambda: self.dev_mode,
            log=self.state.log)
        self.rest_ctx = RestContext(
            persistence=self.persistence, tokens=self.tokens, state=self.state,
            dispatcher=self.dispatcher, clock=clock,
            dev_mode=lambda: self.dev_mode,
            reboot_hook=self._on_reboot,
            scan_hook=self.esp.scan,
            machine_serial=config.serial,
        )
        self.wss: Optional[WssServer] = None
        self.http: Optional[RestServer] = None
        self.redirect: Optional[RedirectServer] = None
        self.control: Optional[ControlServer] = None
        self._stop = threading.Event()
        self._tick_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None

    # -- persisted ConfigManager rows -------------------------------------
    def _load_persisted_settings(self) -> None:
        language = self.persistence.get_setting("System.Language")
        if language:
            self.state.language = language
        wizard = self.persistence.get_setting("System.SetupWizard.State")
        if wizard:
            self.state.setup_wizard_state = wizard
        owner = self.persistence.get_setting("Role.Owner.LoginData")
        if owner is not None:
            self.state.owner_login_data = owner

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        self.esp.start()
        self.state.esp.alive = True
        # The vendor HMI polls the ESP JSON peer at start-up; sdioStatus=1 is
        # the "Init" value observed in the baseline driver state.
        self.esp.request_sdio_status()
        self.persistence.write_static_config(self.state)
        self.persistence.save_state_view(self.state)
        self.wss = WssServer((self.config.bind, self.config.wss_port),
                             self.tokens, self.dispatcher,
                             self.config.certfile, self.config.keyfile)
        threading.Thread(target=self.wss.serve_forever, daemon=True,
                         name="wss").start()
        if self.config.https_port:
            self.redirect = RedirectServer(
                (self.config.bind, self.config.http_port),
                self.config.https_port)
            self.http = RestServer(
                (self.config.bind, self.config.https_port),
                self.rest_ctx, debug=self.config.debug,
                certfile=self.config.certfile, keyfile=self.config.keyfile)
            threading.Thread(target=self.redirect.serve_forever, daemon=True,
                             name="redirect").start()
        else:
            self.http = RestServer((self.config.bind, self.config.http_port),
                                   self.rest_ctx, debug=self.config.debug)
        threading.Thread(target=self.http.serve_forever, daemon=True,
                         name="http").start()
        self._tick_thread = threading.Thread(target=self._tick_loop, daemon=True,
                                             name="tick")
        self._tick_thread.start()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="espjson-ping")
        self._heartbeat_thread.start()
        if self.config.control_socket:
            control_state = ControlState(self, self.config.state_dir)
            self.control = ControlServer(self.config.control_socket,
                                         control_state)
            self.control.serve()

    def _heartbeat_loop(self) -> None:
        """HMI -> ESP JSON heartbeat every 500 ms (ESPU-01)."""
        while not self._stop.wait(0.5):
            try:
                self.esp.ping()
            except Exception:  # noqa: BLE001 - a dead UART must not kill the HMI
                pass

    def _tick_loop(self) -> None:
        last_view = None
        while not self._stop.wait(self.config.tick_interval):
            self.state.tick()
            view = (self.state.backlight_brightness, self.state.backlight_power,
                    self.state.nozzle_light, self.state.grind.state)
            if view != last_view:
                self.persistence.save_state_view(self.state)
                last_view = view
            if self.state.grind.state == "Done" and not getattr(
                    self, "_grind_logged", False):
                self.persistence.add_grind(self.state)
                self._grind_logged = True
            elif self.state.grind.state != "Done":
                self._grind_logged = False

    def _on_reboot(self) -> None:
        self.state.log("reboot requested")
        self.state.emit("reboot", {})
        if os.environ.get("E64CTL_REBOOT_CMD"):
            os.system(os.environ["E64CTL_REBOOT_CMD"])  # noqa: S605 - opt-in

    def stop(self) -> None:
        self._stop.set()
        if self.control is not None:
            self.control.close()
        if self.wss is not None:
            self.wss.shutdown()
            self.wss.server_close()
        if self.http is not None:
            self.http.shutdown()
            self.http.server_close()
        if self.redirect is not None:
            self.redirect.shutdown()
            self.redirect.server_close()
        self.esp.stop()
        self.persistence.close()

    def wait(self) -> None:
        while not self._stop.wait(0.5):
            pass


def build_self_signed(certfile: str, keyfile: str) -> None:
    """Generate a throwaway self-signed cert (vendor uses /db/webui.crt|key)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
    except ImportError:
        os.system(f'openssl req -x509 -newkey rsa:2048 -nodes -keyout "{keyfile}"'
                  f' -out "{certfile}" -days 365 -subj "/CN=e64ws.local"')
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e64ws.local")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    with open(keyfile, "wb") as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(certfile, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="e64ctl", description=__doc__)
    parser.add_argument("--state-dir", default="/tmp/e64ctl")
    parser.add_argument("--wss-port", type=int, default=9997)
    parser.add_argument("--http-port", type=int, default=8080,
                        help="plain HTTP port (redirects to TLS with --https-port)")
    parser.add_argument("--https-port", type=int, default=None,
                        help="serve the REST surface over TLS on this port")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--dev-mode", dest="dev_mode", action="store_true",
                        default=None, help="force /etc/issue dev gate open")
    parser.add_argument("--no-dev-mode", dest="dev_mode", action="store_false")
    parser.add_argument("--issue-file", default="/etc/issue")
    parser.add_argument("--tls", action="store_true",
                        help="serve wss:// with a self-signed certificate")
    parser.add_argument("--certfile")
    parser.add_argument("--keyfile")
    parser.add_argument("--esp-device", help="/dev/esps0 or unix:/path")
    parser.add_argument("--esp-json-device", help="/dev/ttySTM1 or unix:/path")
    parser.add_argument("--no-esp-sim", action="store_true",
                        help="do not start the built-in ESP simulator")
    parser.add_argument("--serial", default="000000")
    parser.add_argument("--grinder-type", type=int, default=0)
    parser.add_argument("--grinder-type-name", default="E64 WS")
    parser.add_argument("--control-socket",
                        help="Unix socket for the differential harness")
    parser.add_argument("--no-motion-sim", dest="motion_sim",
                        action="store_false",
                        help="no load-cell/motor source: grind stays Idle")
    parser.add_argument("--live-profile", action="store_true",
                        help="seed the sanitized 2026-11-18 live E64 profile")
    parser.add_argument("--weight-trace",
                        help="replay a grind_capture JSONL weight trace")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--print-registry", action="store_true")
    args = parser.parse_args(argv)

    if args.print_registry:
        for rec in COMMANDS:
            print(jsonfmt.dumps({
                "type": rec.type, "action": rec.action, "log": rec.log,
                "dev": rec.dev, "token": rec.token, "elf": rec.elf,
            }, indented=False))
        return 0

    certfile, keyfile = args.certfile, args.keyfile
    if args.tls and not (certfile and keyfile):
        certfile = os.path.join(args.state_dir, "webui.crt")
        keyfile = os.path.join(args.state_dir, "webui.key")
        os.makedirs(args.state_dir, exist_ok=True)
        if not (os.path.exists(certfile) and os.path.exists(keyfile)):
            build_self_signed(certfile, keyfile)

    config = ServiceConfig(
        state_dir=args.state_dir, wss_port=args.wss_port,
        http_port=args.http_port, https_port=args.https_port,
        bind=args.bind, dev_mode=args.dev_mode,
        issue_file=args.issue_file, certfile=certfile, keyfile=keyfile,
        esp_device=args.esp_device, esp_json_device=args.esp_json_device,
        simulate_esp=not args.no_esp_sim, serial=args.serial,
        grinder_type=args.grinder_type,
        grinder_type_name=args.grinder_type_name,
        control_socket=args.control_socket, motion_sim=args.motion_sim,
        live_profile=args.live_profile, weight_trace=args.weight_trace,
        debug=args.debug,
    )
    service = Service(config)
    service.start()
    print(f"e64ctl: wss://{config.bind}:{config.wss_port}"
          f"{' (plain ws)' if not certfile else ''}  "
          f"http://{config.bind}:{config.http_port}  "
          f"dev_mode={service.dev_mode}", flush=True)

    def _signal(_signum, _frame):
        service._stop.set()

    signal.signal(signal.SIGINT, _signal)
    signal.signal(signal.SIGTERM, _signal)
    try:
        service.wait()
    finally:
        service.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
