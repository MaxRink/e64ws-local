"""Registry and dispatcher unit tests (no sockets)."""
from __future__ import annotations

import unittest

from harness import Harness  # noqa: F401  (sys.path setup)
from e64ctl import registry
from e64ctl.dispatch import Dispatcher, UNKNOWN_TYPE_BODY
from e64ctl.handlers import Handlers
from e64ctl.state import DeviceState
from e64ctl.tokens import TokenStore


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def build(dev: bool = True, clock=None):
    clock = clock or FakeClock()
    state = DeviceState(clock=clock)
    tokens = TokenStore("/tmp", clock=clock)
    handlers = Handlers(state)
    dispatcher = Dispatcher(handlers, tokens, lambda: dev)
    return state, tokens, handlers, dispatcher


class RegistryTests(unittest.TestCase):
    def test_counts(self) -> None:
        self.assertEqual(len(registry.COMMANDS), 52)
        self.assertEqual(len(registry.DIRECT), 13)
        self.assertEqual(len(registry.ACTIONS), 39)
        self.assertEqual(sum(1 for c in registry.COMMANDS if c.token), 51)
        self.assertEqual(sum(1 for c in registry.COMMANDS if c.dev), 44)
        no_token = [c.type for c in registry.COMMANDS if not c.token]
        self.assertEqual(no_token, ["RequestOnboarding"])
        self.assertEqual(
            [c.action for c in registry.ACTIONS if not c.dev],
            ["EspReset", "ResetDriverConfig"])

    def test_all_types_unique_for_direct(self) -> None:
        direct_types = [c.type for c in registry.DIRECT]
        self.assertEqual(len(direct_types), len(set(direct_types)))

    def test_action_lookup(self) -> None:
        self.assertEqual(registry.lookup("GrinderAction", "Stop").action, "Stop")
        self.assertIsNone(registry.lookup("GrinderAction", "stop"))
        self.assertIsNone(registry.lookup("GrinderAction", None))
        self.assertEqual(registry.lookup("RequestDriverState", None).type,
                         "RequestDriverState")

    def test_live_set_without_dev(self) -> None:
        live = {c.type if c.action is None else c.action
                for c in registry.live_commands(False)}
        self.assertEqual(live, {
            "RequestDriverConfig", "RequestDriverState", "RequestNachineInfo",
            "RequestOnboarding", "WifiStaConfig", "WifiConfigChanged",
            "EspReset", "ResetDriverConfig",
        })


class DispatcherTests(unittest.TestCase):
    def test_dev_gate_closes_without_response(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=False)
        token = tokens.mint("s", "Owner")
        outcome = dispatcher.handle_message(
            {"type": "GrinderAction", "msgId": 1,
             "data": {"actionType": "StartGrindGbw", "targetWeightGr": 18}},
            tokens.consume(token))
        self.assertFalse(outcome.accepted)
        self.assertIsNone(outcome.response)

    def test_every_action_dispatches_in_dev_mode(self) -> None:
        for rec in registry.ACTIONS:
            with self.subTest(action=rec.action):
                state, tokens, handlers, dispatcher = build(dev=True)
                token = tokens.consume(tokens.mint("s", "Owner"))
                outcome = dispatcher.handle_message(
                    {"type": "GrinderAction", "msgId": 7,
                     "data": {"actionType": rec.action}}, token)
                self.assertTrue(outcome.accepted, rec.action)
                if rec.action == "GbsCreateReport":
                    self.assertEqual(outcome.response["type"], "GbsCreateReport")
                    continue
                self.assertEqual(outcome.response["type"], "GrinderActionResult")
                self.assertEqual(outcome.response["refId"], 7)
                self.assertIn("success", outcome.response["data"])

    def test_every_direct_dispatches_in_dev_mode(self) -> None:
        for rec in registry.DIRECT:
            with self.subTest(type=rec.type):
                state, tokens, handlers, dispatcher = build(dev=True)
                token = tokens.consume(tokens.mint("s", "Owner"))
                outcome = dispatcher.handle_message(
                    {"type": rec.type, "msgId": 3, "data": {}}, token)
                self.assertTrue(outcome.accepted, rec.type)
                self.assertIsNotNone(outcome.response)

    def test_token_required(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        outcome = dispatcher.handle_message(
            {"type": "RequestDriverState", "msgId": 1}, None)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reject_reason, "invalid token")

    def test_expired_token(self) -> None:
        clock = FakeClock()
        state, tokens, handlers, dispatcher = build(dev=True, clock=clock)
        token = tokens.consume(tokens.mint("s", "Owner", ttl=300))
        clock.now += 400
        outcome = dispatcher.handle_message(
            {"type": "RequestDriverState", "msgId": 1}, token)
        self.assertFalse(outcome.accepted)

    def test_onboarding_needs_no_token(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        outcome = dispatcher.handle_message(
            {"type": "RequestOnboarding", "msgId": 1, "data": {}}, None)
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.response,
                         {"type": "RequestOnboardingResult",
                          "data": {"success": True}})

    def test_action_requires_nonempty_data(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        token = tokens.consume(tokens.mint("s", "Owner"))
        for payload in ({"type": "GrinderAction", "msgId": 1},
                        {"type": "GrinderAction", "msgId": 1, "data": {}},
                        {"type": "GrinderAction", "msgId": 1,
                         "data": {"actionType": "Nope"}}):
            with self.subTest(payload=payload):
                self.assertFalse(
                    dispatcher.handle_message(payload, token).accepted)

    def test_token_refresh(self) -> None:
        clock = FakeClock()
        state, tokens, handlers, dispatcher = build(dev=True, clock=clock)
        token = tokens.consume(tokens.mint("s", "Owner", ttl=300))
        clock.now += 200
        before = token.expires
        dispatcher.handle_message({"type": "RequestDriverState", "msgId": 1},
                                  token)
        self.assertGreater(token.expires, before)

    def test_unknown_body_shape(self) -> None:
        self.assertEqual(UNKNOWN_TYPE_BODY["type"], "UnknownType")
        self.assertEqual(UNKNOWN_TYPE_BODY["data"], {"success": False})

    def test_case_sensitive_type(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        token = tokens.consume(tokens.mint("s", "Owner"))
        outcome = dispatcher.handle_message(
            {"type": "requestdriverstate", "msgId": 1}, token)
        self.assertFalse(outcome.accepted)


class EnvelopeTests(unittest.TestCase):
    def test_direct_envelope_uses_msgid(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        token = tokens.consume(tokens.mint("s", "Owner"))
        for msg_id in (0, 5, 99999):
            outcome = dispatcher.handle_message(
                {"type": "RequestAdcConfig", "msgId": msg_id}, token)
            self.assertEqual(outcome.response["refId"], msg_id)
            self.assertEqual(outcome.response["type"],
                             "RequestAdcConfigResult")

    def test_wifi_responses(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        token = tokens.consume(tokens.mint("s", "Owner"))
        r1 = dispatcher.handle_message(
            {"type": "WifiStaConfig", "msgId": 1,
             "data": {"ssid": "n", "password": "p", "dhcp": True}},
            token).response
        self.assertEqual(r1, {"type": "WifiStaConfig",
                              "data": {"success": True}})
        r2 = dispatcher.handle_message(
            {"type": "WifiConfigChanged", "msgId": 2,
             "data": {"ssid": "n"}}, token).response
        self.assertEqual(r2, {"type": "WifiConfigChangedProcessed",
                              "data": {"success": True}})

    def test_update_commands_report_false(self) -> None:
        state, tokens, handlers, dispatcher = build(dev=True)
        token = tokens.consume(tokens.mint("s", "Owner"))
        for wire in ("UpdateDriverConfig", "UpdateCpuConfig"):
            outcome = dispatcher.handle_message(
                {"type": wire, "msgId": 4, "data": {"a": 1}}, token)
            self.assertEqual(outcome.response["data"], {"success": False})


if __name__ == "__main__":
    unittest.main()
