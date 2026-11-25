"""End-to-end WebSocket tests: handshake, token, envelopes, close-on-reject."""
from __future__ import annotations

import json
import unittest

from harness import Harness
from wsclient import WsClient


class WssTests(unittest.TestCase):
    def test_ping_without_token(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(None)
            self.assertEqual(client.request({"ping": True}), {"pong": True})
            client.close()

    def test_direct_commands(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(h.token())
            response = client.request({"type": "RequestDriverState", "msgId": 1})
            self.assertEqual(response["type"], "RequestDriverStateResult")
            self.assertEqual(response["refId"], 1)
            self.assertEqual(response["data"]["grindState"], "Idle")

            response = client.request({"type": "RequestNachineInfo", "msgId": 2})
            self.assertEqual(set(response["data"]), {"sessionId", "grinderType"})
            client.close()

    def test_wire_format_is_qt_indented(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(h.token())
            client.send({"type": "RequestDriverState", "msgId": 1})
            payload = client.recv()
            text = payload.decode()
            self.assertTrue(text.startswith('{\n    "data": {'))
            self.assertIn('"type": "RequestDriverStateResult"', text)
            self.assertTrue(text.endswith("}\n"))
            client.close()

    def test_unknown_type_closes(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(h.token())
            client.send({"type": "Bogus", "msgId": 1})
            self.assertIsNone(client.recv(1.0))
            self.assertTrue(client.closed)

    def test_dev_gate_closes(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(h.token())
            client.send({"type": "GrinderAction", "msgId": 1,
                         "data": {"actionType": "StartGrindGbw",
                                  "targetWeightGr": 18.0}})
            self.assertIsNone(client.recv(1.0))
            self.assertTrue(client.closed)

    def test_token_required_closes(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(None)
            client.send({"type": "RequestDriverState", "msgId": 1})
            self.assertIsNone(client.recv(1.0))
            self.assertTrue(client.closed)

    def test_dev_mode_all_actions(self) -> None:
        with Harness(dev_mode=True) as h:
            client = h.client(h.token())
            response = client.request({
                "type": "GrinderAction", "msgId": 9,
                "data": {"actionType": "SetFan1Duty", "dutyPercent": 55}})
            self.assertEqual(response, {"type": "GrinderActionResult",
                                        "refId": 9,
                                        "data": {"success": True}})
            self.assertEqual(h.state.fans[0].duty, 55)

            response = client.request({
                "type": "GrinderAction", "msgId": 10,
                "data": {"actionType": "SetLanguage", "language": "de"}})
            self.assertTrue(response["data"]["success"])
            self.assertEqual(h.state.language, "de")
            client.close()

    def test_grind_sequence(self) -> None:
        with Harness(dev_mode=True) as h:
            client = h.client(h.token())
            self.assertTrue(client.request({
                "type": "GrinderAction", "msgId": 1,
                "data": {"actionType": "StartGrindGbw",
                         "targetWeightGr": 18.0}})["data"]["success"])
            self.assertEqual(h.state.grind.state, "Starting")
            self.assertTrue(client.request({
                "type": "GrinderAction", "msgId": 2,
                "data": {"actionType": "Stop"}})["data"]["success"])
            self.assertEqual(h.state.grind.state, "Done")
            client.close()

    def test_multiple_messages_one_socket(self) -> None:
        with Harness(dev_mode=True) as h:
            client = h.client(h.token())
            for index in range(5):
                response = client.request({"type": "RequestDriverState",
                                           "msgId": index})
                self.assertEqual(response["refId"], index)
            client.close()

    def test_token_reuse_second_socket(self) -> None:
        with Harness(dev_mode=False) as h:
            token = h.token()
            first = h.client(token)
            self.assertEqual(first.request({"ping": True}), {"pong": True})
            # The token file is gone after the first validation; the in-memory
            # record still accepts the same token on a second socket.
            second = h.client(token)
            response = second.request({"type": "RequestDriverState", "msgId": 1})
            self.assertIsNotNone(response)
            second.close()
            first.close()

    def test_non_object_and_bad_json_close(self) -> None:
        with Harness(dev_mode=False) as h:
            client = h.client(None)
            client.send({"hello": 1})
            self.assertIsNone(client.recv(1.0))
            self.assertTrue(client.closed)


if __name__ == "__main__":
    unittest.main()
