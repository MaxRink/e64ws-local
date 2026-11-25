import contextlib
import io
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from integrations.decaid.e64ws_adapter import (
    BrewEvent,
    DecaidCapabilityPolicy,
    E64DecaidAdapter,
)
from tools.e64ws_api import E64LocalAPI, E64WSAPIError
from tools import e64ws_cli
from tools.e64ws_protocol import E64WSProtocol
from tools.scale_events import (
    ScaleEventValidationError,
    build_brew_event_find_payload,
    normalize_scale_event,
    parse_cloud_brew_event,
    parse_vendor_brew_event,
)
from tools.gbs_model import (
    DdEffState,
    MODEL_TYPE_ENUM_TO_NAME,
    ROAST_DEGREE_INDEX_TO_NAME,
    SampleHistory,
    SamplePoint,
    GbsV2State,
    GbsV3State,
    GbsV4State,
    V1MedianAverage,
    blend_v2,
    blend_v3_v4,
    cxx_round,
    dd_change_requires_history_reset,
    dd_eff_measurement_sequence,
    firmware_linear_regression_predict,
    gbs_v3_adjust,
    gbs_v2_adjust,
    gbs_v4_adjust,
    hysteretic_quantize,
    linear_regression_predict,
    proposed_dd_from_selection,
    proposed_dd_from_weight,
    output_tenths,
    should_commit_adjustment,
    v1_adjust_from_history,
    v1_adjust,
    v1_central_window_average,
    v1_correction,
)
from tools.decaid_flow import (
    MachineFlowSample,
    build_flow_event,
)
from tools.df_gbs_applet import recommend_manual
from tools.openscale_client import (
    OpenScaleProtocolError,
    OpenScaleSnapshot,
    OpenScaleTypedFrame,
    OpenScaleClient,
    parse_frame,
)
from tools.openscale_shots import OpenScaleShotAccumulator


class ProtocolTests(unittest.TestCase):
    def test_rest_port_is_separate_from_wss_port_for_simulator(self) -> None:
        api = E64LocalAPI(
            "127.0.0.1",
            scheme="ws",
            port=9997,
            rest_port=8787,
            token="test-token",
        )
        self.assertEqual(api.base_url, "http://127.0.0.1:8787")
        api.close()

    def test_ids_are_monotonic_and_action_envelope_is_exact(self) -> None:
        protocol = E64WSProtocol()
        first = protocol.request("RequestDriverState")
        second = protocol.action("SetLanguage", {"language": "en"})
        self.assertEqual(first["msgId"], 1)
        self.assertEqual(second["msgId"], 2)
        self.assertEqual(second["type"], "GrinderAction")
        self.assertEqual(second["data"]["actionType"], "SetLanguage")
        self.assertTrue(E64WSProtocol.matches_response(
            second,
            {"type": "GrinderActionResult", "refId": 2, "data": {"success": True}},
        ))

    def test_hazardous_action_is_guarded_before_connect(self) -> None:
        api = E64LocalAPI("127.0.0.1", insecure=True, token="test-token")
        with self.assertRaises(E64WSAPIError):
            api.ws_action("StartGrindGbw", {"targetWeightGr": 18})
        with self.assertRaises(E64WSAPIError):
            api.ws_request(
                "GrinderAction",
                {"actionType": "StartGrindGbw", "targetWeightGr": 18},
            )
        with self.assertRaises(E64WSAPIError):
            api.ws.request_message(
                {
                    "type": "GrinderAction",
                    "msgId": 1,
                    "data": {"actionType": "StartGrindGbw"},
                }
            )
        with self.assertRaises(E64WSAPIError):
            api.ws_action("UpdateDriverConfig", {}, allow_hazardous=False)
        with self.assertRaises(E64WSAPIError):
            api.ws_request("UpdateDriverConfig", {})
        with self.assertRaises(E64WSAPIError):
            api.reboot()
        api.close()


class AdapterTests(unittest.TestCase):
    def test_conflicting_signals_do_not_select_a_direction(self) -> None:
        recommendation = E64DecaidAdapter.recommend(
            target_brew_time_s=28,
            actual_brew_time_s=22,
            flavor="bitter",
        )
        self.assertEqual(recommendation.direction, "none")
        self.assertTrue(recommendation.requires_confirmation)

    def test_brew_event_injection_is_separate_explicit_opt_in(self) -> None:
        class FakeAPI:
            def ws_action(self, *_args, **_kwargs):
                return {"ok": True}

        event = BrewEvent(
            duration_ms=28_000,
            mass_g=36.0,
            source="openscale",
            shot_id="shot-1",
            grind_uuid="grind-1",
            wire_profile="owner-live-validated-v01.16",
        )
        disabled = E64DecaidAdapter(FakeAPI())
        with self.assertRaises(E64WSAPIError):
            disabled.record_brew_event(event)

        enabled = E64DecaidAdapter(
            FakeAPI(),
            policy=DecaidCapabilityPolicy(
                allow_event_injection=True,
                validated_brew_wire_profile="owner-live-validated-v01.16",
            ),
        )
        self.assertEqual(enabled.record_brew_event(event), {"ok": True})
        self.assertIs(enabled.last_brew_event, event)

    def test_brew_event_invalid_or_unprofiled_fails_before_transport(self) -> None:
        class FakeAPI:
            def __init__(self):
                self.calls = 0

            def ws_action(self, *_args, **_kwargs):
                self.calls += 1
                return {"ok": True}

        api = FakeAPI()
        adapter = E64DecaidAdapter(
            api,
            policy=DecaidCapabilityPolicy(
                allow_event_injection=True,
                validated_brew_wire_profile="owner-profile",
            ),
        )
        invalid = BrewEvent(
            duration_ms=28_000,
            mass_g=36.0,
            valid=False,
            source="openscale",
            shot_id="shot-invalid",
            wire_profile="owner-profile",
        )
        with self.assertRaises(E64WSAPIError):
            adapter.record_brew_event(invalid)
        unprofiled = BrewEvent(
            duration_ms=28_000,
            mass_g=36.0,
            source="openscale",
            shot_id="shot-unprofiled",
            wire_profile="other-profile",
        )
        with self.assertRaises(E64WSAPIError):
            adapter.record_brew_event(unprofiled)
        self.assertEqual(api.calls, 0)

    def test_actuation_requires_bounds_snapshot_and_rate_gate(self) -> None:
        class FakeAPI:
            def driver_state(self):
                return {"data": {"grindFailure": False, "ddSensorAngle": 12}}

            def ws_action(self, *_args, **_kwargs):
                return {"ok": True}

        adapter = E64DecaidAdapter(
            FakeAPI(),
            policy=DecaidCapabilityPolicy(
                allow_actuation=True,
                dd_bounds=(0, 100),
                min_actuation_interval_s=60,
            ),
        )
        adapter.snapshot()
        self.assertEqual(adapter.set_agsa_target_dd(20), {"ok": True})
        with self.assertRaises(E64WSAPIError):
            adapter.set_agsa_target_dd(21)
        self.assertTrue(any(entry.operation == "grinder.actuate" for entry in adapter.audit_log()))


class ScaleEventTests(unittest.TestCase):
    def test_exact_nested_cloud_event_and_query(self) -> None:
        payload = build_brew_event_find_payload("g-1", "2026-08-25T10:00:00Z")
        self.assertEqual(
            payload,
            {
                "grinderId": "g-1",
                "deviceDateRange": {"from": "2026-08-25T10:00:00Z"},
            },
        )
        event = parse_cloud_brew_event(
            {
                "eventUuid": "event-1",
                "deviceId": "scale-1",
                "brewer": {
                    "brewer": "scale",
                    "groupNumber": "4",
                    "doseIndex": "doubleShot",
                    "doseType": "doubleCup",
                    "validity": False,
                    "duration": 25_000,
                    "volume": 40,
                    "mass": 36_000,
                    "grindEventUuid": "grind-1",
                    "stopTarget": 36.0,
                },
                "cloudDate": "2026-08-25T10:00:00Z",
            }
        )
        self.assertEqual(event.value("duration"), 25_000)
        self.assertEqual(event.value("mass"), 36_000)
        self.assertEqual(event.value("groupNumber"), "0")
        self.assertEqual(event.value("doseType"), "MassType")
        self.assertEqual(event.value("stopTarget"), 36_000.0)
        normalized = normalize_scale_event(
            event,
            duration_unit="ms",
            mass_unit="mg",
        )
        self.assertAlmostEqual(normalized.duration_s, 25.0)
        self.assertAlmostEqual(normalized.mass_g, 36.0)
        self.assertEqual(normalized.grind_event_uuid, "grind-1")

    def test_exact_cloud_discriminator_and_integer_checks(self) -> None:
        with self.assertRaises(ScaleEventValidationError):
            parse_cloud_brew_event(
                {
                    "eventUuid": "e",
                    "deviceId": "d",
                    "brewer": {"brewer": "unknown", "duration": 1},
                    "grindEventUuid": "g",
                }
            )
        with self.assertRaises(ScaleEventValidationError):
            parse_cloud_brew_event(
                {
                    "eventUuid": "e",
                    "deviceId": "d",
                    "brewer": {"brewer": "scale", "duration": 1.5, "mass": 2},
                    "grindEventUuid": "g",
                }
            )

    def test_parser_preserves_recovered_vendor_key_spellings(self) -> None:
        payload = {
            "eventUuid": "event-1",
            "deviceId": "scale-1",
            "brewer": {"type": "Hemro Scale"},
            "groupNumber": 1,
            "doseIndex": 0,
            "doseType": "espresso",
            "validity": True,
            "duration": 28000,
            "volume": 36,
            "mass": 36,
            "grindEventUuid": "grind-1",
            "stopTarget": 36,
            "cloudDate": "2026-08-25T10:00:00Z",
        }
        event = parse_vendor_brew_event(
            payload,
            required_fields=("eventUuid", "deviceId", "duration", "mass", "validity"),
        )
        normalized = normalize_scale_event(
            event, duration_unit="ms", mass_unit="g", volume_unit="ml"
        )
        self.assertEqual(normalized.event_uuid, "event-1")
        self.assertAlmostEqual(normalized.duration_s, 28.0)
        self.assertAlmostEqual(normalized.mass_g, 36.0)
        self.assertEqual(normalized.raw["grindEventUuid"], "grind-1")

    def test_parser_rejects_bad_common_types(self) -> None:
        with self.assertRaises(ScaleEventValidationError):
            parse_vendor_brew_event({"eventUuid": 7})
        with self.assertRaises(ScaleEventValidationError):
            parse_vendor_brew_event({"duration": float("nan")})
        with self.assertRaises(ScaleEventValidationError):
            normalize_scale_event(
                {"eventUuid": "e", "deviceId": "d", "duration": 1, "mass": 1, "validity": True},
                duration_unit="unknown",
                mass_unit="g",
            )


class GbsModelTests(unittest.TestCase):
    def test_decoded_dial_in_formula(self) -> None:
        self.assertEqual(
            proposed_dd_from_weight(18_000, model="e64", roast="dark"), 83
        )
        self.assertEqual(
            proposed_dd_from_weight(18_000, model="e64", roast="light"), 43
        )

    def test_decoded_dial_in_numeric_selection_mapping(self) -> None:
        self.assertEqual(MODEL_TYPE_ENUM_TO_NAME, {1: "e64", 2: "e65", 3: "e80"})
        self.assertEqual(
            ROAST_DEGREE_INDEX_TO_NAME, {0: "light", 1: "medium", 2: "dark"}
        )
        self.assertEqual(
            proposed_dd_from_selection(
                18_000, model_enum=1, roast_degree_index=0
            ),
            43,
        )
        self.assertEqual(
            proposed_dd_from_selection(
                18_000, model_enum=2, roast_degree_index=2
            ),
            92,
        )
        with self.assertRaises(ValueError):
            proposed_dd_from_selection(
                18_000, model_enum=4, roast_degree_index=0
            )
        with self.assertRaises(ValueError):
            proposed_dd_from_selection(
                18_000, model_enum=1, roast_degree_index=3
            )

    def test_decoded_v1_and_blends(self) -> None:
        adjustment = v1_adjust(central=10.0, observation=12.0, previous_state=10.0)
        self.assertEqual(adjustment.correction, -5.0)
        self.assertEqual(adjustment.output_tenths, 50)
        self.assertAlmostEqual(blend_v2(10.0, 20.0), 19.0)
        self.assertAlmostEqual(blend_v3_v4(10.0, 20.0), 16.0)

    def test_documented_gbs_algorithm_examples(self) -> None:
        v1 = v1_adjust(
            central=20.0,
            observation=25.0,
            previous_state=10.0,
            previous_output_tenths=100,
        )
        self.assertEqual(v1.output_tenths, 50)

        points = (
            SamplePoint(50.0, 30.0),
            SamplePoint(45.0, 32.0),
            SamplePoint(40.0, 34.0),
            SamplePoint(35.0, 36.0),
        )
        prediction = firmware_linear_regression_predict(points, 28.0)
        self.assertAlmostEqual(prediction, 52.5)
        self.assertEqual(output_tenths(blend_v2(50.0, prediction)), 523)

        v2_state = GbsV2State()
        v2 = gbs_v2_adjust(
            v2_state,
            actual_ms=30_000,
            target_ms=28_000,
            estimated_dd_dum=500,
            setpoint_dd_dum=500,
            tolerance_ms=1_000,
        )
        self.assertTrue(v2.committed)
        self.assertEqual(len(v2_state.history), 1)
        self.assertEqual(v2_state.last_result_dum, v2.returned_dum)
        restored = GbsV2State.from_json(v2_state.to_json())
        self.assertEqual(restored.to_json(), v2_state.to_json())

        v3_state = GbsV3State(hold_cycles_remaining=0, mid_factor=0.0)
        v3 = gbs_v3_adjust(
            v3_state,
            actual_ms=20_000,
            target_ms=25_000,
            estimated_dd_dum=500,
            setpoint_dd_dum=600,
            tolerance_ms=0,
        )
        self.assertEqual((v3.phase, v3.returned_dum), ("mid", 400))

        v4_state = GbsV4State(
            history=SampleHistory(
                (
                    SamplePoint(50.0, 20.0),
                    SamplePoint(49.0, 21.0),
                    SamplePoint(48.0, 22.0),
                )
            ),
            hold_cycles_remaining=0,
            last_target_dum=500,
            last_adjustment_dum=510,
        )
        v4_locked = gbs_v4_adjust(
            v4_state,
            actual_ms=22_001,
            target_ms=25_000,
            estimated_dd_dum=505,
            setpoint_dd_dum=500,
            tolerance_ms=0,
        )
        self.assertTrue(v4_locked.locked)
        self.assertEqual(v4_locked.returned_dum, 510)
        v4_boundary = gbs_v4_adjust(
            v4_state,
            actual_ms=22_000,
            target_ms=25_000,
            estimated_dd_dum=505,
            setpoint_dd_dum=500,
            tolerance_ms=0,
        )
        self.assertEqual((v4_boundary.phase, v4_boundary.returned_dum), ("mid", 447))

        self.assertEqual(
            dd_eff_measurement_sequence(1000),
            (1000,) * 6 + (800,) * 6 + (1200,) * 6,
        )
        self.assertEqual(dd_eff_measurement_sequence(1000, calls=19)[-1], 1000)

    def test_v2_uses_setpoint_for_sample_and_blend(self) -> None:
        state = GbsV2State()
        result = gbs_v2_adjust(
            state,
            actual_ms=30_000,
            target_ms=28_000,
            estimated_dd_dum=900,
            setpoint_dd_dum=500,
            tolerance_ms=0,
        )
        # One point (50 um, 30 s) predicts 51 um for a 28 s target. The
        # recovered 10/90 setpoint/prediction blend is 50.9 um -> 509 d-um.
        self.assertEqual(result.candidate_dum, 509)
        self.assertEqual(result.returned_dum, 509)
        self.assertEqual(state.history.as_tuple(), (SamplePoint(50.0, 30.0),))

    def test_v2_tolerance_boundary_and_history_mutation(self) -> None:
        held = GbsV2State(last_result_dum=777)
        inside = gbs_v2_adjust(
            held,
            actual_ms=28_000,
            target_ms=28_000,
            estimated_dd_dum=500,
            setpoint_dd_dum=500,
            tolerance_ms=1,
        )
        self.assertFalse(inside.committed)
        self.assertEqual(inside.returned_dum, 777)
        # The sample is learned before the final output commit gate.
        self.assertEqual(held.history.as_tuple(), (SamplePoint(50.0, 28.0),))

        boundary = GbsV2State(last_result_dum=777)
        equal = gbs_v2_adjust(
            boundary,
            actual_ms=30_000,
            target_ms=28_000,
            estimated_dd_dum=500,
            setpoint_dd_dum=500,
            tolerance_ms=2_000,
        )
        self.assertTrue(equal.committed)
        self.assertEqual(equal.returned_dum, 509)

    def test_v2_six_point_window_reset_and_host_round_trip(self) -> None:
        state = GbsV2State()
        for index in range(7):
            gbs_v2_adjust(
                state,
                actual_ms=30_000 + index * 1_000,
                target_ms=28_000,
                estimated_dd_dum=500,
                setpoint_dd_dum=500 + index * 10,
                tolerance_ms=1_000_000,
            )
        self.assertEqual(
            state.history.as_tuple(),
            tuple(SamplePoint(float(51 + index), float(31 + index)) for index in range(6)),
        )
        restored = GbsV2State.from_json(state.to_json())
        self.assertEqual(restored.to_json(), state.to_json())
        state.reset()
        self.assertEqual(len(state.history), 0)
        self.assertIsNone(state.last_result_dum)
        with self.assertRaises(ValueError):
            GbsV2State.from_json(
                {"history": [{"x": index, "y": index} for index in range(7)]}
            )

    def test_v2_recovered_vendor_json_shape_and_safe_parser(self) -> None:
        empty = GbsV2State()
        self.assertEqual(
            empty.to_vendor_json(),
            {"type": "GbS2", "version": 1, "history": []},
        )
        state = GbsV2State(
            history=SampleHistory((SamplePoint(50.0, 30.0),)),
            last_result_dum=509,
        )
        canonical = {
            "type": "GbS2",
            "version": 1,
            "history": [
                {"effectiveGrindSizeUm": 50.0, "brewDurationSec": 30.0}
            ],
        }
        self.assertEqual(state.to_vendor_json(), canonical)
        self.assertIsNone(GbsV2State.from_vendor_json(canonical).last_result_dum)
        self.assertEqual(
            GbsV2State.from_vendor_json(canonical).to_vendor_json(), canonical
        )
        for invalid in (
            {"type": "GbS3", "version": 1, "history": []},
            {"type": "GbS2", "version": 2, "history": []},
            {"type": "GbS2", "version": 1, "history": {}},
            {
                "type": "GbS2",
                "version": 1,
                "history": [
                    {"effectiveGrindSizeUm": index, "brewDurationSec": index}
                    for index in range(7)
                ],
            },
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    GbsV2State.from_vendor_json(invalid)

    def test_v3_v4_and_ddeff_recovered_vendor_json_shapes(self) -> None:
        v3 = GbsV3State(
            history=SampleHistory((SamplePoint(50.0, 30.0),)),
            filtered_dd_times_brew=1500.0,
            last_target_dum=500,
            last_adjustment_dum=510,
        )
        v3_restored = GbsV3State.from_vendor_json(v3.to_vendor_json())
        self.assertEqual(v3_restored.to_vendor_json(), v3.to_vendor_json())

        v4 = GbsV4State(
            history=SampleHistory((SamplePoint(50.0, 30.0),)),
            filtered_dd_times_brew=1500.0,
            hold_cycles_remaining=1,
            last_target_dum=500,
            last_adjustment_dum=510,
        )
        v4_restored = GbsV4State.from_vendor_json(v4.to_vendor_json())
        self.assertEqual(v4_restored.to_vendor_json(), v4.to_vendor_json())

        ddeff = DdEffState(500)
        self.assertEqual(ddeff.to_vendor_json(), {
            "type": "DdEff",
            "version": 1,
            "initialCoarsenessDum": 500,
        })
        self.assertEqual(ddeff.next(), 500)
        self.assertEqual(DdEffState.from_vendor_json(ddeff.to_vendor_json()).calls, 0)

    def test_v1_cubic_quantizer_and_rolling_ages(self) -> None:
        # Raw correction = -((32768 / 5**3) + 0.2) * 0.01.
        self.assertAlmostEqual(
            v1_correction(central=10.0, observation=10.01),
            -2.62344,
        )
        adjustment = v1_adjust(
            central=10.0,
            observation=10.01,
            previous_state=10.0,
            previous_output_tenths=100,
        )
        # The <=0.5-second median/target deadband retains the prior output.
        self.assertTrue(adjustment.within_error_window)
        self.assertEqual(adjustment.output_tenths, 100)
        self.assertEqual(hysteretic_quantize(10.16, 10.0), 10.0)
        self.assertAlmostEqual(hysteretic_quantize(10.160001, 10.0), 10.2)
        # The binary's C++ floating-point division is just below 50.5 here;
        # C round therefore selects 10.0, unlike a decimal-arithmetic model.
        self.assertAlmostEqual(hysteretic_quantize(10.1, None), 10.0)

        history = V1MedianAverage()
        self.assertEqual(history.append(20.0), 20.0)
        self.assertEqual([record.age for record in history.records()], [0, 1, 2, 3])
        self.assertEqual(history.append(30.0), 20.0)
        self.assertEqual(sorted(record.age for record in history.records()), [0, 1, 2, 3])
        self.assertEqual(history.append(10.0), 20.0)
        self.assertEqual(history.append(40.0), 25.0)

    def test_firmware_signed_rounding(self) -> None:
        self.assertEqual(cxx_round(2.5), 3)
        self.assertEqual(cxx_round(-2.5), -3)
        self.assertEqual(output_tenths(1.25), 13)
        self.assertEqual(output_tenths(-1.25), -13)

    def test_v3_phases_and_estimated_dd_times_brew(self) -> None:
        state = GbsV3State(hold_cycles_remaining=0, mid_factor=0.0)
        result = gbs_v3_adjust(
            state,
            actual_ms=20_000,
            target_ms=25_000,
            estimated_dd_dum=500,
            setpoint_dd_dum=600,
            tolerance_ms=0,
        )
        self.assertEqual(result.phase, "mid")
        # estimated 50um * 20s / 25s = 40um, proving the estimated operand.
        self.assertEqual(result.returned_dum, 400)

        state.history.append(SamplePoint(50.0, 20.0))
        state.history.append(SamplePoint(49.0, 21.0))
        near = gbs_v3_adjust(
            state,
            actual_ms=23_000,
            target_ms=25_000,
            estimated_dd_dum=500,
            setpoint_dd_dum=500,
            tolerance_ms=0,
        )
        self.assertEqual(near.phase, "near")
        self.assertEqual(state.hold_cycles_remaining, 2)

    def test_v4_lock_in_and_strict_near_boundary(self) -> None:
        history = SampleHistory(
            (
                SamplePoint(50.0, 20.0),
                SamplePoint(49.0, 21.0),
                SamplePoint(48.0, 22.0),
            )
        )
        state = GbsV4State(
            history=history,
            hold_cycles_remaining=0,
            last_target_dum=500,
            last_adjustment_dum=510,
        )
        locked = gbs_v4_adjust(
            state,
            actual_ms=22_001,
            target_ms=25_000,
            estimated_dd_dum=505,
            setpoint_dd_dum=500,
            tolerance_ms=0,
        )
        self.assertTrue(locked.locked)
        self.assertEqual(locked.returned_dum, 510)
        self.assertEqual(len(state.history), 3)

        boundary = gbs_v4_adjust(
            state,
            actual_ms=22_000,
            target_ms=25_000,
            estimated_dd_dum=505,
            setpoint_dd_dum=500,
            tolerance_ms=0,
        )
        self.assertFalse(boundary.locked)
        self.assertEqual(boundary.phase, "mid")

    def test_decoded_v1_central_window(self) -> None:
        observations = (1.0, 2.0, 3.0, 4.0, 5.0, 6.0)
        self.assertAlmostEqual(
            v1_central_window_average(observations, window_width=3), 4.0
        )
        # available = 6 - (3 - 1) = 4, so start = floor(4 / 2) = 2.
        self.assertAlmostEqual(
            v1_adjust_from_history(
                observations,
                window_width=3,
                observation=4.0,
                previous_state=10.0,
            ).central,
            4.0,
        )
        with self.assertRaises(ValueError):
            v1_central_window_average((1.0, 2.0), window_width=3)

    def test_history_and_guards(self) -> None:
        history = SampleHistory()
        for index in range(8):
            history.append(SamplePoint(float(index), float(index * 2)))
        self.assertEqual(len(history), 6)
        self.assertAlmostEqual(
            linear_regression_predict(history.as_tuple(), 10.0), 20.0
        )
        self.assertFalse(dd_change_requires_history_reset(100, 600))
        self.assertTrue(dd_change_requires_history_reset(100, 601))
        self.assertTrue(should_commit_adjustment(3.0, 3.0))
        self.assertFalse(should_commit_adjustment(2.99, 3.0))

    def test_firmware_regression_orientation_and_guards(self) -> None:
        self.assertAlmostEqual(
            firmware_linear_regression_predict((SamplePoint(10.0, 20.0),), 18.0),
            11.0,
        )
        # Positive slope is clamped to -0.5 by the recovered firmware branch.
        result = firmware_linear_regression_predict(
            tuple(SamplePoint(float(x), float(2 * x)) for x in range(4)),
            2.0,
        )
        self.assertAlmostEqual(result, 3.5)


class OpenScaleTests(unittest.TestCase):
    def test_snapshot_and_typed_frames(self) -> None:
        snapshot = parse_frame('{"grams": 25.66, "ms": 12345}')
        self.assertIsInstance(snapshot, OpenScaleSnapshot)
        self.assertAlmostEqual(snapshot.grams, 25.66)
        status = parse_frame({"type": "status", "grams": 25.66})
        self.assertIsInstance(status, OpenScaleTypedFrame)
        with self.assertRaises(OpenScaleProtocolError):
            parse_frame({"grams": float("nan"), "ms": 1})

    def test_safe_transport_does_not_expose_destructive_controls(self) -> None:
        class FakeSocket:
            def __init__(self):
                self.sent = []

            def send(self, value):
                self.sent.append(value)

            def close(self):
                pass

            def recv(self):
                return '{"grams": 1.0, "ms": 2}'

        socket = FakeSocket()
        client = OpenScaleClient(
            "hds.local", websocket_factory=lambda *_args, **_kwargs: socket
        )
        self.assertEqual(client.url, "ws://hds.local/snapshot")
        client.set_rate(10)
        self.assertEqual(socket.sent, ["rate 10k"])
        self.assertIsInstance(client.recv_frame(), OpenScaleSnapshot)
        with self.assertRaises(OpenScaleProtocolError):
            client.send_safe("power off")

    def test_standalone_shot_requires_explicit_boundaries_and_stable_samples(self) -> None:
        accumulator = OpenScaleShotAccumulator(
            metadata={"device_id": "hds.local", "rate_hz": 10},
            connection_id="conn-1",
        )
        accumulator.start(boundary_origin="user_timer")
        accumulator.add_snapshot(OpenScaleSnapshot(0.0, 1000.0, {}), sequence=1)
        accumulator.add_snapshot(OpenScaleSnapshot(36.0, 2000.0, {}), sequence=2)
        accumulator.add_snapshot(OpenScaleSnapshot(36.1, 3000.0, {}), sequence=3)
        accumulator.add_snapshot(OpenScaleSnapshot(36.1, 4000.0, {}), sequence=4)
        shot = accumulator.finish()
        self.assertTrue(shot.valid)
        self.assertEqual(shot.validity, "valid")
        self.assertEqual(shot.boundary_origin, "user_timer")
        self.assertEqual(shot.metadata["device_id"], "hds.local")
        self.assertEqual(shot.samples[-1].sequence, 4)

    def test_standalone_shot_marks_timestamp_fault_invalid(self) -> None:
        accumulator = OpenScaleShotAccumulator(stable_sample_count=1)
        accumulator.start()
        accumulator.add_snapshot(OpenScaleSnapshot(1.0, 1000.0, {}), sequence=1)
        accumulator.add_snapshot(OpenScaleSnapshot(1.0, 1000.0, {}), sequence=2)
        shot = accumulator.finish()
        self.assertFalse(shot.valid)
        self.assertIn("timestamp", shot.reason)

    def test_standalone_shot_rejects_typed_frames_and_aborts_disconnect(self) -> None:
        accumulator = OpenScaleShotAccumulator(stable_sample_count=1)
        accumulator.start(started_ms=0.0, boundary_origin="machine_shot")
        with self.assertRaises(OpenScaleProtocolError):
            accumulator.add_frame({"type": "status", "grams": 0.0})
        accumulator.add_snapshot(
            OpenScaleSnapshot(1.0, 1000.0, {"grams": 1.0, "ms": 1000.0}),
            sequence=1,
        )
        shot = accumulator.abort("scale stream disconnected")
        self.assertFalse(shot.valid)
        self.assertEqual(shot.validity, "invalid")
        self.assertEqual(shot.reason, "scale stream disconnected")
        self.assertEqual(shot.boundary_origin, "machine_shot")


class FlowOnlyTests(unittest.TestCase):
    def test_flow_event_never_becomes_mass_or_sync_event(self) -> None:
        now = datetime.now(timezone.utc)
        samples = [
            MachineFlowSample(0.0, 0.0, now, 1, "c1", "de1"),
            MachineFlowSample(1.2, 250.0, now, 2, "c1", "de1"),
            MachineFlowSample(1.1, 1000.0, now, 3, "c1", "de1"),
        ]
        event = build_flow_event(samples, target_hz=2)
        self.assertTrue(event.valid)
        self.assertEqual(len(event.samples), 3)
        self.assertEqual(len(event.analysis_samples), 2)
        self.assertIsNone(event.mass_g)
        self.assertEqual(event.sync_scale_validity, "not_evaluable")
        self.assertFalse(event.e64_injection_eligible)

    def test_flow_event_marks_source_order_fault(self) -> None:
        now = datetime.now(timezone.utc)
        samples = [
            MachineFlowSample(1.0, 1000.0, now, 1, "c1", "de1"),
            MachineFlowSample(1.0, 900.0, now, 2, "c1", "de1"),
        ]
        event = build_flow_event(samples)
        self.assertFalse(event.valid)
        self.assertIn("timestamp", event.invalid_reason or "")

    def test_flow_event_rejects_mid_shot_source_identity_change(self) -> None:
        now = datetime.now(timezone.utc)
        samples = [
            MachineFlowSample(1.0, 1000.0, now, 1, "c1", "de1", "fw-a", 10),
            MachineFlowSample(1.0, 1100.0, now, 2, "c1", "de1", "fw-b", 20),
        ]
        event = build_flow_event(samples)
        self.assertFalse(event.valid)
        self.assertIn("source firmware", event.invalid_reason or "")
        self.assertIn("declared cadence", event.invalid_reason or "")


class DfAppletTests(unittest.TestCase):
    def test_df_profiles_are_recommendation_only_and_need_calibrated_numeric_sign(self) -> None:
        recommendation = recommend_manual(
            profile="df64_gen1",
            target_time_s=30,
            actual_time_s=20,
            flavor="too acidic",
            current_dial=15,
            step_marks=1,
        )
        self.assertEqual(recommendation.direction, "finer")
        self.assertEqual(recommendation.physical_turn, "clockwise")
        self.assertIsNone(recommendation.proposed_dial)
        numeric = recommend_manual(
            profile="df64_gen1",
            target_time_s=30,
            actual_time_s=20,
            current_dial=15,
            step_marks=1,
            numeric_finer_delta=-1,
        )
        self.assertEqual(numeric.proposed_dial, 14)

    def test_df_conflicting_signals_require_confirmation(self) -> None:
        recommendation = recommend_manual(
            profile="df54",
            target_time_s=30,
            actual_time_s=20,
            flavor="too bitter",
        )
        self.assertEqual(recommendation.direction, "none")
        self.assertIsNone(recommendation.physical_turn)
        self.assertTrue(recommendation.requires_confirmation)


class CliSessionTests(unittest.TestCase):
    def test_wss_token_does_not_suppress_explicit_rest_login(self) -> None:
        class FakeAPI:
            last = None

            def __init__(self, _host, *, token=None, **_kwargs):
                self.token = token
                self.login_calls = []
                self.rest_calls = []
                FakeAPI.last = self

            def login(self, role, password):
                self.login_calls.append((role, password))
                self.token = "new-token"

            def rest(self, route, data=None):
                self.rest_calls.append((route, data))
                return {"ok": True}

            def close(self):
                pass

        output = io.StringIO()
        with patch.object(e64ws_cli, "E64LocalAPI", FakeAPI), contextlib.redirect_stdout(output):
            self.assertEqual(
                e64ws_cli.main(
                    ["--host", "local", "--token", "wss-token", "rest", "ping"]
                ),
                0,
            )
        self.assertEqual(FakeAPI.last.login_calls, [])
        self.assertEqual(FakeAPI.last.rest_calls, [("ping", None)])

        output = io.StringIO()
        with patch.object(e64ws_cli, "E64LocalAPI", FakeAPI), contextlib.redirect_stdout(output):
            self.assertEqual(
                e64ws_cli.main(
                    [
                        "--host", "local", "--token", "wss-token", "--role", "Owner",
                        "--password", "pw", "rest", "download_database",
                    ]
                ),
                0,
            )
        self.assertEqual(FakeAPI.last.login_calls, [("Owner", "pw")])

    def test_cli_reboot_requires_explicit_opt_in(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            e64ws_cli.main(["--host", "local", "--token", "wss-token", "reboot"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
