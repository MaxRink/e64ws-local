"""ESP control-plane tests: framing, protobuf schema, all 21 request pairs."""
from __future__ import annotations

import os
import tempfile
import time
import unittest

from harness import free_port  # noqa: F401  (sys.path setup)
from e64ctl import esp as espmod
from e64ctl.esp import (
    CtrlMsg, EspClient, EspSimulator, EspTransport, SimEspState, decode_frame,
    encode_frame, frame_length,
)


class FramingTests(unittest.TestCase):
    def test_published_vectors(self) -> None:
        # docs/API_REFERENCE.md: Req_SetWifiMode{mode=1}
        request = bytes.fromhex(
            "01 08 00 63 74 72 6c 52 65 73 70 02 09 00 "
            "08 01 10 68 c2 06 02 08 01")
        self.assertEqual(frame_length(request), len(request))
        endpoint, msg = decode_frame(request)
        self.assertEqual(endpoint, b"ctrlResp")
        self.assertEqual((msg.msg_type, msg.msg_id), (1, 104))
        self.assertEqual(msg.payload, {"mode": 1})
        # Resp_SetWifiMode{resp=0}
        expected = bytes.fromhex(
            "01 08 00 63 74 72 6c 52 65 73 70 02 08 00 "
            "08 02 10 cc 01 e2 0c 00")
        reply = encode_frame(CtrlMsg(2, 204, {"resp": 0}))
        self.assertEqual(reply, expected)

    def test_roundtrip_every_request(self) -> None:
        payloads = {
            101: {"mode": 0}, 102: {"mac": b"\x01\x02\x03\x04\x05\x06", "mode": 0},
            103: {}, 104: {"mode": 3}, 105: {}, 106: {}, 108: {}, 109: {},
            112: {}, 113: {}, 114: {"mode": 1}, 115: {}, 116: {},
            117: {"ota_data": b"\xaa\xbb"}, 118: {},
            119: {"wifi_max_tx_power": 15}, 120: {},
            121: {"enable": True, "duration": 500},
            107: {"ssid": "abc", "pwd": "def", "bssid": "", "is_wpa3_supported": False,
                  "listen_interval": 3},
            110: {"enable": True, "type": 0, "idx": 1,
                  "vendor_ie_data": {"element_id": 221, "length": 3,
                                     "vendor_oui": b"\x00\x11\x22",
                                     "vendor_oui_type": 1, "payload": b"\x09"}},
            111: {"ssid": "ap", "pwd": "pw", "chnl": 6, "sec_prot": 3,
                  "max_conn": 4, "ssid_hidden": False, "bw": 1},
        }
        self.assertEqual(set(payloads), set(espmod.REQ_FIELDS))
        for msg_id, payload in payloads.items():
            with self.subTest(msg_id=msg_id):
                frame = encode_frame(CtrlMsg(1, msg_id, payload))
                _, decoded = decode_frame(frame)
                self.assertEqual(decoded.msg_id, msg_id)
                for key, value in payload.items():
                    if isinstance(value, dict):
                        self.assertEqual(decoded.payload[key], value)
                    else:
                        self.assertEqual(decoded.payload[key], value)

    def test_rejects_bad_header(self) -> None:
        good = encode_frame(CtrlMsg(1, 104, {"mode": 1}))
        for index, value in ((0, 0x02), (1, 0x09), (11, 0x03)):
            broken = bytearray(good)
            broken[index] = value
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    frame_length(bytes(broken))

    def test_events(self) -> None:
        for msg_id, payload in ((301, {"init_data": b"\x01"}),
                                (302, {"hb_num": 3}),
                                (303, {"resp": 1}),
                                (304, {"resp": 1, "mac": b"\x01" * 6})):
            frame = encode_frame(CtrlMsg(3, msg_id, payload),
                                 endpoint=b"ctrlEvnt")
            endpoint, decoded = decode_frame(frame)
            self.assertEqual(endpoint, b"ctrlEvnt")
            self.assertEqual((decoded.msg_type, decoded.msg_id), (3, msg_id))
            self.assertEqual(decoded.payload, payload)


class SimulatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="e64-esp-")
        self.device = os.path.join(self.dir, "esps0")
        self.sim = EspSimulator(self.device, SimEspState(
            scan_results=[{"ssid": b"Test", "chnl": 6, "rssi": -50,
                           "bssid": b"\x02\x00\x00\x00\x00\x01",
                           "sec_prot": 3}]))
        self.sim.start()
        self.client = EspClient(EspTransport(self.device))
        self.client.start()

    def tearDown(self) -> None:
        self.client.stop()
        self.sim.stop()

    def call(self, msg_id: int, payload=None):
        reply = self.client.request(msg_id, payload or {}, timeout=1.0)
        self.assertIsNotNone(reply, msg_id)
        self.assertEqual(reply.msg_id, msg_id + 100)
        return reply.payload

    def test_all_pairs(self) -> None:
        self.assertEqual(self.call(101, {"mode": 0})["resp"], 0)
        self.assertEqual(self.call(102, {"mac": b"\x02" * 6, "mode": 0})["resp"], 0)
        self.assertEqual(self.call(103)["mode"], 0)
        self.assertEqual(self.call(104, {"mode": 1})["resp"], 0)
        scan = self.call(105)
        self.assertEqual(scan["count"], 1)
        self.assertEqual(scan["entries"][0]["ssid"], b"Test")
        self.assertEqual(self.call(106)["resp"], 1)          # not connected
        connected = self.call(107, {"ssid": b"Test", "pwd": b"pw", "bssid": b""})
        self.assertEqual(connected["resp"], 0)
        self.assertEqual(self.call(106)["resp"], 0)
        self.assertEqual(self.call(108)["resp"], 0)
        self.assertEqual(self.call(109)["chnl"], 6)
        self.assertEqual(self.call(110, {"enable": True, "type": 0, "idx": 0,
                                         "vendor_ie_data": {}})["resp"], 0)
        started = self.call(111, {"ssid": b"ap", "pwd": b"pw", "chnl": 6,
                                  "sec_prot": 3, "max_conn": 4,
                                  "ssid_hidden": False, "bw": 1})
        self.assertEqual(started["resp"], 0)
        self.assertEqual(self.call(112)["num"], 1)
        self.assertEqual(self.call(113)["resp"], 0)
        self.assertEqual(self.call(114, {"mode": 1})["resp"], 0)
        self.assertEqual(self.call(115)["mode"], 1)
        self.assertEqual(self.call(116)["resp"], 0)
        self.assertEqual(self.call(117, {"ota_data": b"x" * 10})["resp"], 0)
        self.assertEqual(self.call(118)["resp"], 0)
        self.assertEqual(self.call(119, {"wifi_max_tx_power": 10})["resp"], 0)
        self.assertEqual(self.call(120)["wifi_curr_tx_power"], 10)
        self.assertEqual(self.call(121, {"enable": True, "duration": 1000})["resp"], 0)

    def test_limits(self) -> None:
        self.assertEqual(self.call(107, {"ssid": b"x" * 33})["resp"], 4)
        self.assertEqual(self.call(107, {"ssid": b"x", "pwd": b"x" * 65})["resp"], 4)
        self.assertEqual(self.call(107, {"ssid": b"x", "bssid": b"x" * 19})["resp"], 4)
        self.assertEqual(self.call(104, {"mode": 9})["resp"], 5)
        self.assertEqual(self.call(114, {"mode": 0})["resp"], 5)
        self.assertEqual(self.call(116)["resp"], 0)
        self.assertEqual(self.call(117, {"ota_data": b""})["resp"], 4)
        self.assertEqual(self.call(118)["resp"], 0)


class EspBridgeJsonTests(unittest.TestCase):
    def test_json_uart(self) -> None:
        from e64ctl.esp_bridge import EspBridge

        bridge = EspBridge(simulate=True)
        bridge.start()
        try:
            self.assertTrue(bridge.ping())
            version = bridge.request_version()
            self.assertEqual(version["versionNo"], bridge.json_state.version_no)
            status = bridge.request_sdio_status()
            self.assertEqual(status["sdioStatus"], 1)
            self.assertFalse(status["fuseFailed"])
            bridge.start_function("Standby", color=1)
            time.sleep(0.1)
            self.assertEqual(bridge.json_simulator.state.last_function["color"], 1)
        finally:
            bridge.stop()


if __name__ == "__main__":
    unittest.main()
