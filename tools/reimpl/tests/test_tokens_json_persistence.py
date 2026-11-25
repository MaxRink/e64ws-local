"""Token, JSON formatting and persistence tests."""
from __future__ import annotations

import json
import os
import time
import unittest

from harness import Harness  # noqa: F401
from e64ctl import jsonfmt
from e64ctl.persistence import (
    GRIND_CSV_COLUMNS, SERVICE_CSV_COLUMNS, Persistence,
)
from e64ctl.state import DeviceState
from e64ctl.tokens import TokenStore, is_token_shaped


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class TokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.dir = f"/tmp/e64-tok-{os.getpid()}"
        os.makedirs(self.dir, exist_ok=True)
        self.store = TokenStore(self.dir, clock=self.clock)

    def tearDown(self) -> None:
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_shape(self) -> None:
        token = self.store.mint("s", "Owner")
        self.assertTrue(is_token_shaped(token))
        self.assertEqual(len(token), 64)

    def test_file_format(self) -> None:
        token = self.store.mint("session-1", "Owner")
        path = self.store.path_for(token)
        self.assertTrue(os.path.exists(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        record = json.load(open(path))
        self.assertEqual(set(record), {"sessionId", "token", "role", "expires"})
        self.assertEqual(record["sessionId"], "session-1")
        self.assertEqual(record["expires"], int(self.clock.now) + 300)

    def test_validate_deletes_file_and_keeps_memory(self) -> None:
        token = self.store.mint("s", "Owner")
        record = self.store.consume(token)
        self.assertIsNotNone(record)
        self.assertFalse(os.path.exists(self.store.path_for(token)))
        again = self.store.consume(token)
        self.assertIsNotNone(again)

    def test_expiry(self) -> None:
        token = self.store.mint("s", "Owner")
        self.clock.now += 301
        self.assertIsNone(self.store.consume(token))

    def test_missing_role_rejected(self) -> None:
        token = self.store.mint("s", "")
        self.assertIsNone(self.store.consume(token))

    def test_refresh(self) -> None:
        token = self.store.mint("s", "Owner")
        record = self.store.consume(token)
        self.clock.now += 200
        self.store.refresh(record)
        self.clock.now += 200
        self.assertIsNotNone(self.store.consume(token))

    def test_unknown_token(self) -> None:
        self.assertIsNone(self.store.consume("0" * 64))
        self.assertIsNone(self.store.consume(None))
        self.assertIsNone(self.store.consume(""))


class JsonFormatTests(unittest.TestCase):
    def test_indented(self) -> None:
        text = jsonfmt.dumps({"type": "X", "refId": 1, "data": {"ok": True}})
        # QJsonObject keeps keys sorted, so toJson() emits data, refId, type.
        self.assertEqual(text, (
            '{\n'
            '    "data": {\n'
            '        "ok": true\n'
            '    },\n'
            '    "refId": 1,\n'
            '    "type": "X"\n'
            '}\n'))

    def test_compact(self) -> None:
        self.assertEqual(jsonfmt.dumps({"a": [1, 2], "b": None}, indented=False),
                         '{"a":[1,2],"b":null}')

    def test_escapes(self) -> None:
        self.assertEqual(jsonfmt.dumps({"k": 'a"b\\c\n\t\x01'}, indented=False),
                         '{"k":"a\\"b\\\\c\\n\\t\\u0001"}')
        self.assertEqual(jsonfmt.dumps({"k": "ü"}, indented=False),
                         '{"k":"ü"}')

    def test_numbers(self) -> None:
        self.assertEqual(jsonfmt.dumps({"a": 18.0, "b": 18.5, "c": 0.1},
                                       indented=False),
                         '{"a":18,"b":18.5,"c":0.1}')

    def test_empty_containers(self) -> None:
        self.assertEqual(jsonfmt.dumps({}, indented=False), "{}")
        self.assertEqual(jsonfmt.dumps([], indented=False), "[]")


class PersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = f"/tmp/e64-db-{os.getpid()}"
        self.clock = Clock()
        self.p = Persistence(self.root, clock=self.clock)
        self.state = DeviceState(clock=self.clock)

    def tearDown(self) -> None:
        self.p.close()
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_schema(self) -> None:
        tables = {row[0] for row in self.p.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("settings", "grind_log", "brew_events", "event_types",
                      "event_log", "alert_types", "alert_log", "recipe_data",
                      "recipe_entries", "portafilters", "gbs_algo_state"):
            self.assertIn(table, tables)

    def test_grind_row(self) -> None:
        self.state.grind.result_weight_gr = 18.25
        self.state.grind.motor_run_time_ms = 7200
        row_id = self.p.add_grind(self.state)
        self.assertGreater(row_id, 0)
        rows = self.p.grind_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["grind_weight"], 18250)
        self.assertEqual(rows[0]["grind_duration"], 7200)

    def test_csv_columns(self) -> None:
        # sqlite3 -header -csv prints nothing at all for an empty result.
        self.assertEqual(
            self.p.export_csv(self.p.grind_rows(), GRIND_CSV_COLUMNS), "")
        self.assertEqual(
            self.p.export_csv(self.p.service_rows(), SERVICE_CSV_COLUMNS), "")
        self.p.add_grind(self.state)
        text = self.p.export_csv(self.p.grind_rows(), GRIND_CSV_COLUMNS)
        header = text.splitlines()[0]
        self.assertEqual(header.split(","), GRIND_CSV_COLUMNS)
        self.assertTrue(text.endswith("\r\n"))
        self.p.add_event(3, "grind")
        service = self.p.export_csv(self.p.service_rows(), SERVICE_CSV_COLUMNS)
        self.assertEqual(service.splitlines()[0].split(","), SERVICE_CSV_COLUMNS)

    def test_log_zip(self) -> None:
        self.p.add_grind(self.state)
        self.p.add_event(3, "grind")
        target, data = self.p.build_log_zip("123456")
        self.assertTrue(data.startswith(b"PK"))
        import zipfile
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
        self.assertEqual(len(names), 2)
        self.assertTrue(names[0].startswith("HemroHsgGrindLogs_SN123456_"))

    def test_empty_log_zip_matches_vendor_zip(self) -> None:
        # The pristine DB has no rows, so the vendor's two ``sqlite3 -header
        # -csv`` files are zero bytes and ``zip -j`` produces a 490-byte
        # archive (two stored members + UT/ux extras).
        target, data = self.p.build_log_zip("0123456789AB")
        self.assertEqual(len(data), 490)
        import zipfile
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
            self.assertTrue(names[0].startswith(
                "HemroHsgGrindLogs_SN0123456789AB_"))
            self.assertTrue(names[1].startswith(
                "HemroHsgServiceLogs_SN0123456789AB_"))
            self.assertEqual([i.file_size for i in archive.infolist()], [0, 0])

    def test_settings_roundtrip(self) -> None:
        self.p.set_setting("language", "de")
        self.assertEqual(self.p.get_setting("language"), "de")
        self.assertEqual(self.p.get_setting("missing", "x"), "x")

    def test_wifi_config_file(self) -> None:
        self.state.sta.ssid = "Net"
        self.state.sta.password = "pw"
        self.p.save_wifi_config(self.state)
        payload = self.p.read_json("/db/wifiConfig.json")
        self.assertEqual(payload["staSsid"], "Net")
        self.assertEqual(payload["staPassword"], "pw")
        self.assertEqual(set(payload), {
            "mode", "apSsid", "apPassword", "apIp", "staSsid", "staPassword",
            "staDhcp", "staStaticGateway", "staStaticDns", "staStaticIp",
            "staStaticNetmask"})


if __name__ == "__main__":
    unittest.main()
