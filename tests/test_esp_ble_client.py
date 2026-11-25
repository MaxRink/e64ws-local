"""Tests for the host-side E64 ESP32 BLE JSON client.

No radio is used: a fake transport records writes and injects notifications.
"""

from __future__ import annotations

import asyncio
import unittest

from tools.esp_ble_client import BleJsonClient, BleJsonError, MAX_PAYLOAD, RX_UUID, TX_UUID


class FakeTransport:
    def __init__(self, reply: bytes | None = b'{"pong":true}', delay: float = 0.0) -> None:
        self.reply = reply
        self.delay = delay
        self.callback = None
        self.writes: list[bytes] = []
        self.disconnected = False

    async def start_notify(self, uuid, callback):
        assert uuid == TX_UUID
        self.callback = callback

    async def write_gatt_char(self, uuid, data, response=True):
        assert uuid == RX_UUID
        self.writes.append(data)
        if self.reply is not None:
            loop = asyncio.get_running_loop()
            loop.call_later(self.delay, self.callback, None, self.reply)

    async def disconnect(self):
        self.disconnected = True


class BleJsonClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_ping_roundtrip(self) -> None:
        transport = FakeTransport()
        client = BleJsonClient("fake", timeout=1.0, transport_factory=lambda _: _done(transport))
        value = await client.request({"ping": True})
        self.assertEqual(value, {"pong": True})
        self.assertEqual(transport.writes, [b'{"ping":true}'])
        await client.close()
        self.assertTrue(transport.disconnected)

    async def test_no_response_mode(self) -> None:
        transport = FakeTransport(reply=None)
        client = BleJsonClient("fake", timeout=1.0, transport_factory=lambda _: _done(transport))
        self.assertIsNone(await client.request({"type": "StartFunction"}, expect_response=False))
        self.assertEqual(len(transport.writes), 1)

    async def test_timeout(self) -> None:
        transport = FakeTransport(reply=None)
        client = BleJsonClient("fake", timeout=0.05, transport_factory=lambda _: _done(transport))
        with self.assertRaises(BleJsonError):
            await client.request({"ping": True})

    async def test_bad_notification(self) -> None:
        transport = FakeTransport(reply=b"not json")
        client = BleJsonClient("fake", timeout=1.0, transport_factory=lambda _: _done(transport))
        with self.assertRaises(BleJsonError):
            await client.request({"ping": True})

    async def test_payload_limit(self) -> None:
        transport = FakeTransport()
        client = BleJsonClient("fake", timeout=1.0, transport_factory=lambda _: _done(transport))
        with self.assertRaises(BleJsonError):
            await client.request("x" * (MAX_PAYLOAD + 1))
        self.assertEqual(transport.writes, [])


async def _done(value):
    return value


if __name__ == "__main__":
    unittest.main()
