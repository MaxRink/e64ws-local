"""Shared test harness: an isolated service instance on ephemeral ports."""
from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from e64ctl.main import Service, ServiceConfig  # noqa: E402


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Harness:
    def __init__(self, dev_mode: bool = False, clock=None) -> None:
        self.dir = tempfile.mkdtemp(prefix="e64-test-")
        self.config = ServiceConfig(
            state_dir=self.dir,
            wss_port=free_port(),
            http_port=free_port(),
            dev_mode=dev_mode,
            serial="123456",
        )
        self.service = Service(self.config, clock=clock) if clock else \
            Service(self.config)
        self.dev_mode = dev_mode

    def __enter__(self) -> "Harness":
        self.service.start()
        time.sleep(0.15)
        return self

    def __exit__(self, *exc) -> None:
        self.service.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    # -- helpers ----------------------------------------------------------
    def token(self, role: str = "Owner") -> str:
        return self.service.tokens.mint("session-" + role, role)

    def client(self, token: str | None = None):
        from wsclient import WsClient

        return WsClient(port=self.config.wss_port, token=token).connect()

    @property
    def state(self):
        return self.service.state

    @property
    def http_port(self) -> int:
        return self.config.http_port
