#!/usr/bin/env python3
"""Host-side client for the E64 ESP32 local BLE JSON bridge.

The firmware exposes one custom GATT service:

    service 8ec90001-f315-4f60-9fb8-838830daea50
    RX      8ec90002-f315-4f60-9fb8-838830daea50  write
    TX      8ec90003-f315-4f60-9fb8-838830daea50  notify

The payload is the same JSON document as the UART2 control link.  This client
uses Bleak (optional) and is intentionally small: connect, subscribe, write one
request and wait for one notification.  It is not a scale client and does not
claim hardware validation.

Examples:
    python3 tools/esp_ble_client.py --scan
    python3 tools/esp_ble_client.py --address AA:BB:CC:DD:EE:FF --json '{"ping":true}'
    python3 tools/esp_ble_client.py --address ... --json '{"type":"RequestVersion"}'
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, Awaitable, Callable, Protocol

SERVICE_UUID = "8ec90001-f315-4f60-9fb8-838830daea50"
RX_UUID = "8ec90002-f315-4f60-9fb8-838830daea50"
TX_UUID = "8ec90003-f315-4f60-9fb8-838830daea50"
DEVICE_NAME = "Ng2EspApp"
MAX_PAYLOAD = 512


class Transport(Protocol):
    async def start_notify(self, uuid: str, callback: Callable[[Any, bytearray], None]) -> None: ...
    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = True) -> None: ...
    async def disconnect(self) -> None: ...


class BleJsonError(RuntimeError):
    pass


class BleJsonClient:
    def __init__(
        self,
        address: str,
        *,
        timeout: float = 5.0,
        transport_factory: Callable[[str], Awaitable[Transport]] | None = None,
    ) -> None:
        self.address = address
        self.timeout = timeout
        self._factory = transport_factory
        self._transport: Transport | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def connect(self) -> None:
        if self._transport is not None:
            return
        if self._factory is not None:
            transport = await self._factory(self.address)
        else:
            try:
                from bleak import BleakClient  # type: ignore[import-not-found]
            except ImportError as exc:
                raise BleJsonError("BLE transport requires the optional bleak package") from exc
            transport = BleakClient(self.address, timeout=self.timeout)
            await transport.connect()
        self._transport = transport
        await transport.start_notify(TX_UUID, self._on_notify)

    def _on_notify(self, _sender: Any, data: bytearray | bytes) -> None:
        self._queue.put_nowait(bytes(data))

    async def request(self, payload: dict[str, Any] | str, *, expect_response: bool = True) -> dict[str, Any] | None:
        text = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
        if not text:
            raise BleJsonError("empty request")
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_PAYLOAD:
            raise BleJsonError(f"request exceeds {MAX_PAYLOAD} bytes")
        await self.connect()
        assert self._transport is not None
        while not self._queue.empty():
            self._queue.get_nowait()
        await self._transport.write_gatt_char(RX_UUID, encoded, response=True)
        if not expect_response:
            return None
        try:
            raw = await asyncio.wait_for(self._queue.get(), timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise BleJsonError("timed out waiting for a BLE notification") from exc
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BleJsonError(f"notification is not JSON: {raw!r}") from exc
        if not isinstance(value, dict):
            raise BleJsonError("notification JSON is not an object")
        return value

    async def close(self) -> None:
        if self._transport is not None:
            try:
                await self._transport.disconnect()
            finally:
                self._transport = None


async def scan(timeout: float = 5.0) -> list[dict[str, Any]]:
    try:
        from bleak import BleakScanner  # type: ignore[import-not-found]
    except ImportError as exc:
        raise BleJsonError("scanning requires the optional bleak package") from exc
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    out = []
    for address, (device, adv) in found.items():
        name = device.name or adv.local_name or ""
        if name == DEVICE_NAME or SERVICE_UUID.lower() in {u.lower() for u in (adv.service_uuids or [])}:
            out.append({"address": address, "name": name, "rssi": adv.rssi})
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="E64 ESP32 local BLE JSON client")
    parser.add_argument("--address", help="BLE address/identifier of Ng2EspApp")
    parser.add_argument("--scan", action="store_true", help="scan for Ng2EspApp and exit")
    parser.add_argument("--json", default='{"ping":true}', help="JSON request payload")
    parser.add_argument("--no-response", action="store_true", help="do not wait for a notification")
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser


async def run(args: argparse.Namespace) -> int:
    if args.scan:
        for item in await scan(args.timeout):
            print(json.dumps(item, sort_keys=True))
        return 0
    if not args.address:
        raise SystemExit("--address or --scan is required")
    client = BleJsonClient(args.address, timeout=args.timeout)
    try:
        value = await client.request(args.json, expect_response=not args.no_response)
        if value is not None:
            print(json.dumps(value, sort_keys=True))
    finally:
        await client.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(run(args))
    except BleJsonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
