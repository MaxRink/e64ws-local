"""Tests for ``tools/api_coverage.py``.

Why: a coverage checker that cannot fail is decoration.  Every gate the checker
claims to enforce is exercised here on a synthetic tree that mirrors the real
one, so a regression in the reader (a table parser that silently returns zero
rows, a PHP reader that skips the catalog) shows up as a failing test rather
than as a green run over a shrinking matrix.

The fixture tree is deliberately complete: it satisfies every gate, including
the quirk checks, so each test can break exactly one thing and assert the exact
gap the checker reports.  One further test runs the same checker over the real
repository, which is the assertion that the shipped documentation is complete.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

try:  # imported as ``tools.test_api_coverage``
    from . import api_coverage as coverage
except ImportError:  # imported from inside ``tools/``
    import api_coverage as coverage  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]


def fixture() -> dict[str, str]:
    """Return a complete, passing miniature of the repository."""
    return {
        "ondevice/rest_api_dev.php": """<?php
/*
 * Dev gate: requires isDev() == true (first token of /etc/issue == "development").
 */
if ( !function_exists( "isDev" ) || !isDev() )
{
\texit;
}
define( "E64LOCAL_TOKEN_FILE", "/db/e64local/token" );
define( "MAX_REQUEST_BYTES", 16384 );
define( "MAX_ROWS_GRIND_LOG", 5000 );
define( "MAX_ROWS_SERVICE_LOG", 5000 );
define( "MAX_ROWS_ALERT_LOG", 5000 );
define( "E64LOCAL_BOOT_ID_FILE", "/proc/sys/kernel/random/boot_id" );
define( "E64LOCAL_ACTION_AUDIT_MAX_BYTES", 1048576 );
define( "E64LOCAL_ACTION_AUDIT_KEEP", 3 );
$E64LOCAL_ROUTES = array(
\t"ping",
\t"pong",
);
$E64LOCAL_ACTION_META_ROUTES = array(
\t"action_prepare",
);
$E64LOCAL_ACTION_DEFAULT_RATES = array(
\t"grind_start" => array( "perMinute" => 6, "perHour" => 30 ),
);
function _actionCatalog()
{
\tstatic $catalog = null;
\tif ( $catalog !== null )
\t{
\t\treturn $catalog;
\t}
\t$catalog = array(
\t\t"action_grind_start_gbw" => array(
\t\t\t"risk" => "actuator",
\t\t\t"status" => "implemented",
\t\t\t"surface" => "wss",
\t\t\t"command" => "StartGrindGbw",
\t\t\t"bucket" => "grind_start",
\t\t\t"destructive" => false,
\t\t),
\t\t"action_fan_calibrate" => array(
\t\t\t"risk" => "actuator",
\t\t\t"status" => "unavailable",
\t\t\t"code" => 422,
\t\t\t"reason" => "no recovered completion signal",
\t\t),
\t);
\treturn $catalog;
}
function _checkOwnerToken( $postContent )
{
\t$_SERVER["HTTP_X_E64_LOCAL_TOKEN"];
}
function _handleActionRoute( $route )
{
\tswitch ( $route )
\t{
\t\tcase "action_prepare":
\t\t\treturn true;
\t}
\treturn false;
}
function restApiDev( $requestUri )
{
\tswitch ( $requestUri )
\t{
\t\tcase "ping":
\t\t\treturn true;
\t\tcase "pong":
\t\t\treturn true;
\t\tcase "action_prepare":
\t\t\treturn true;
\t\tdefault:
\t\t\tif ( _actionIsBoundaryName( $requestUri ) )
\t\t\t{
\t\t\t\t_failResponse( $returnJson, $success, $returnVal, 403, "outside this API" );
\t\t\t}
\t\t\t_failResponse( $returnJson, $success, $returnVal, 404, "action identifiers are not HTTP paths; use action_prepare" );
\t\t\treturn false;
\t}
}
function _actionRunJob( $jobId )
{
\t$command = escapeshellarg( $sudo ) . " -n " . escapeshellarg( E64LOCAL_ACTION_RUNNER );
\t$error = "the action runner did not return a result";
\t$code = 503;
}
function _actionBootMatchesRecord( $record )
{
\t$error = "the device has rebooted since this action was prepared";
\t$code = 409;
}
function _actionCheckRate()
{
\t$nanoseconds = hrtime( true );
}
function _unused( $postContent )
{
\t_failResponse( $returnJson, $success, $returnVal, 400, "bad input" );
\t_failResponse( $returnJson, $success, $returnVal, 401, "owner token required" );
\t_failResponse( $returnJson, $success, $returnVal, 413, "request body too large (max 16384 bytes)" );
}
""",
        "docs/LOCAL_API.md": """# Local Owner HTTP API v1

The module refuses to answer unless `isDev()` is true, which means the first
word of `/etc/issue` is `development`.

## 2. Authentication

Send the owner token as `X-E64-Local-Token: <token>`, or as `"token"` in the
body. The file is `/db/e64local/token`.

## 3. Transport

- Request size limit: 16,384 bytes (16 KiB).
- Rows per page: 5,000.

### 3.2 HTTP status versus `errorCode`

| `errorCode` | Meaning | Typical HTTP status |
|---:|---|---:|
| 400 | Validation error | 400 |
| 401 | Owner token missing | 400 |
| 403 | MobileApp session | 400 |
| 413 | Request body over 16 KiB | 400 |

## 4. Route table

| Route | Method | Auth | Parameters |
|---|---|---|---|
| `ping` | POST | session + token | none |
| `pong` | POST | session + token | none |
| `action_prepare` | POST | session + token | `route` |

## 6. Limits

| Limit | Value | Applies to |
|---|---:|---|
| Request body | 16,384 bytes | Every route |

## 7.1 Codes

| `errorCode` | When |
|---:|---|
| 400 | Bad input |
| 401 | Owner token missing |
| 403 | Gate closed |
| 413 | Body over 16 KiB |
| 422 | Unavailable action |
| 503 | Runner unavailable |

## 12.6 Rate limits

| Bucket | Per minute | Per hour |
|---|---:|---:|
| `grind_start` | 6 | 30 |

## 12.7 Error model

| Code | Meaning |
|---:|---|
| 403 | Gate closed; boundary name |
| 404 | Unknown action identifier, or a bare action path |
| 409 | Unusable rate-limit state |
| 422 | Parameter validation, or an unavailable action |
| 503 | Runner unavailable |

## 12.8 Action catalog

| Route | Risk | Vendor surface |
|---|---|---|
| `action_grind_start_gbw` | actuator | WSS `StartGrindGbw` |

| Route | Code | Reason |
|---|---:|---|
| `action_fan_calibrate` | 422 | no recovered completion signal |

## 12.9 Notes

A bare POST to an action identifier is not HTTP paths: the module answers 404,
or 403 for a boundary name. Without the sudoers rule at
`/etc/sudoers.d/e64local` the runner cannot start, and every action returns 503.
A prepared action is bound to the boot id, so a reboot is a 409. Rate-limit
windows are kept in monotonic milliseconds. The audit log rotates at 1 MiB.
""",
        "docs/API_COVERAGE.md": """# API coverage

## Quirks

- dev gate on `/etc/issue`
- vendor session plus owner token
- 16 KiB body limit
- 5000-row page cap
- `action_*` names are not paths
- 422 for unavailable actions
- 503 when the runner cannot start
- 409 on boot-id change
- monotonic rate buckets
- 1 MiB audit rotation
- leaf-certificate pin in both apps (`PinnedTrustManager.kt`, `TLSTrust.swift`)
""",
        "docs/openapi/local-api.yaml": """openapi: 3.1.0
info:
  title: E64 Local Owner API v1
  version: "1"
paths:
  /rest_api/ping:
    post:
      summary: ping
  /rest_api/pong:
    post:
      summary: pong
  /rest_api/action_prepare:
    post:
      summary: prepare an action
""",
        "tools/e64local_actions.py": '''"""Fixture action engine."""

ACTION_META_ROUTES: tuple[str, ...] = ("action_prepare",)

ACTION_CATALOG: dict[str, dict[str, object]] = {
    "action_grind_start_gbw": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "StartGrindGbw", "bucket": "grind_start", "destructive": False,
    },
    "action_fan_calibrate": {
        "risk": "actuator", "status": "unavailable", "code": 422,
        "reason": "no recovered completion signal",
    },
}
''',
        "tools/e64ws_simulator.py": '''"""Fixture simulator."""

try:
    from .e64local_actions import (
        ACTION_META_ROUTES,
    )
except ImportError:
    from e64local_actions import (  # type: ignore[no-redef]
        ACTION_META_ROUTES,
    )

ACTION_SUFFIXES = frozenset(
    {
        "StartGrindGbw",
    }
)


class SimulatedLocalApi:
    ROUTES = ("ping", "pong")
    ACTION_ROUTES = ACTION_META_ROUTES


class Handler:
    def do_POST(self) -> None:
        if command_type == "RequestDriverState":
            return
''',
        "tools/e64root/commands.py": '''"""Fixture deploy commands."""

API_SUDOERS_FILE = "/etc/sudoers.d/e64local"
''',
        "docs/API_REGISTRY.md": """# Native WebSocket command registry

There are 1 direct records and 1 action records.

## Direct records

| Type | log | dev | token | Callback |
|---|---:|---:|---:|---:|
| `RequestDriverState` | 0 | 0 | 1 | `0x003f1910` |

## Action records

| Suffix | Callback | Suffix | Callback |
|---|---:|---|---:|
| `StartGrindGbw` | `0x003f7d00` |  |  |
""",
        "docs/WEBSOCKET_API.md": """# Local WebSocket protocol

## Read-only and configuration commands

`RequestDriverState` asks for the driver state.

## Grinder actions

A grind is started with `GrinderActionStartGrindGbw`.

## Exact command inventory

    RequestDriverState
    GrinderAction
    GrinderActionStartGrindGbw

The standalone `GrinderAction` literal is the registered action dispatch type,
not an incomplete command.
""",
        "apps/android/app/src/main/java/de/mahlkoenig/e64local/device/PinnedTrustManager.kt": """package de.mahlkoenig.e64local.device

class PinnedTrustManager(private val expectedSha256: String?) {
    fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
        val certificate = chain.firstOrNull()
        val algorithm = "SHA-256"
    }
}
""",
        "apps/ios/GrinderCore/Sources/GrinderCore/HTTP/TLSTrust.swift": """import Foundation

public enum TLSTrustPolicy {
    case pinnedLeaf(sha256: String)
}

/// Pinning replaces the CA check with the leaf certificate fingerprint.
""",
    }


def write_tree(root: Path, files: dict[str, str]) -> None:
    """Write *files* below *root*."""
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class FixtureCase(unittest.TestCase):
    """Base class that builds a fresh fixture tree per test."""

    files: dict[str, str]

    def setUp(self) -> None:
        self._scratch = tempfile.TemporaryDirectory(prefix="api_coverage_test_")
        self.addCleanup(self._scratch.cleanup)
        self.root = Path(self._scratch.name)
        self.files = fixture()
        write_tree(self.root, self.files)

    def rewrite(self, relative: str, text: str) -> None:
        self.files[relative] = text
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def report(self) -> coverage.Report:
        return coverage.evaluate(self.root)

    def assert_gap(self, kind: str, record: str) -> coverage.Gap:
        report = self.report()
        keys = {gap.as_key() for gap in report.gaps}
        message = "expected {} / {} in\n{}".format(
            kind, record, "\n".join("  {} {}".format(*gap.as_key()) for gap in report.gaps) or "  (no gaps)"
        )
        self.assertIn((kind, record), keys, message)
        return next(gap for gap in report.gaps if gap.as_key() == (kind, record))

    def assert_no_gap(self, kind: str, record: str) -> None:
        report = self.report()
        keys = {gap.as_key() for gap in report.gaps}
        self.assertNotIn((kind, record), keys)


class CleanFixtureTests(FixtureCase):
    """The complete fixture must pass, or every other test proves nothing."""

    def test_clean_fixture_has_no_gaps(self) -> None:
        report = self.report()
        self.assertEqual([], [gap.as_key() for gap in report.gaps])
        self.assertEqual([], [gap.as_key() for gap in report.stale])
        self.assertTrue(report.ok)

    def test_clean_fixture_matrix_counts(self) -> None:
        counts = {}
        for row in self.report().rows:
            counts[row.kind] = counts.get(row.kind, 0) + 1
        self.assertEqual({"route": 3, "action": 2, "wss": 2}, counts)

    def test_main_exits_zero_on_a_clean_tree(self) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, coverage.main(["--root", str(self.root), "--quiet"]))


class RouteGateTests(FixtureCase):
    """The three failure modes the task names, for HTTP routes."""

    def test_route_implemented_but_undocumented(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            'case "pong":\n\t\t\treturn true;',
            'case "pong":\n\t\t\treturn true;\n\t\tcase "ping2":\n\t\t\treturn true;',
        ).replace('$E64LOCAL_ROUTES = array(\n\t"ping",\n\t"pong",', '$E64LOCAL_ROUTES = array(\n\t"ping",\n\t"pong",\n\t"ping2",')
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("route-implemented-undocumented", "ping2")

    def test_route_documented_but_absent(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace(
            "| `pong` | POST | session + token | none |",
            "| `pong` | POST | session + token | none |\n| `pong2` | POST | session + token | none |",
        )
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_gap("route-documented-absent", "pong2")

    def test_route_documented_with_a_different_method(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace(
            "| `pong` | POST | session + token | none |",
            "| `pong` | GET | session + token | none |",
        )
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_gap("route-method-mismatch", "pong")

    def test_route_advertised_but_not_dispatched(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            '$E64LOCAL_ROUTES = array(\n\t"ping",\n\t"pong",',
            '$E64LOCAL_ROUTES = array(\n\t"ping",\n\t"pong",\n\t"ping3",',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("route-advertised-not-dispatched", "ping3")

    def test_route_dispatched_but_not_advertised(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            'case "pong":\n\t\t\treturn true;',
            'case "pong":\n\t\t\treturn true;\n\t\tcase "ping4":\n\t\t\treturn true;',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("route-dispatched-not-advertised", "ping4")

    def test_route_missing_from_the_simulator(self) -> None:
        simulator = self.files["tools/e64ws_simulator.py"].replace(
            'ROUTES = ("ping", "pong")', 'ROUTES = ("ping",)'
        )
        self.rewrite("tools/e64ws_simulator.py", simulator)
        self.assert_gap("route-missing-simulator", "pong")

    def test_meta_route_missing_from_the_inner_switch(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            'case "action_prepare":\n\t\t\treturn true;\n\t}\n\treturn false;',
            '}\n\treturn false;',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("route-meta-not-routed", "action_prepare")


class OpenApiGateTests(FixtureCase):
    """The OpenAPI file is documentation too, so it is gated the same way."""

    def test_route_missing_from_openapi(self) -> None:
        openapi = self.files["docs/openapi/local-api.yaml"].replace(
            "  /rest_api/pong:\n    post:\n      summary: pong\n", ""
        )
        self.rewrite("docs/openapi/local-api.yaml", openapi)
        self.assert_gap("route-missing-openapi", "pong")

    def test_openapi_extra_path(self) -> None:
        # Appended after the last path, so it stays inside the paths block.
        openapi = self.files["docs/openapi/local-api.yaml"] + (
            "  /rest_api/ping_ghost:\n    post:\n      summary: ghost\n"
        )
        self.rewrite("docs/openapi/local-api.yaml", openapi)
        self.assert_gap("openapi-extra-path", "/rest_api/ping_ghost")

    def test_openapi_different_method(self) -> None:
        openapi = self.files["docs/openapi/local-api.yaml"].replace(
            "  /rest_api/pong:\n    post:", "  /rest_api/pong:\n    get:"
        )
        self.rewrite("docs/openapi/local-api.yaml", openapi)
        self.assert_gap("openapi-method-mismatch", "pong")

    def test_openapi_without_a_paths_block_is_an_input_error(self) -> None:
        self.rewrite("docs/openapi/local-api.yaml", "openapi: 3.1.0\ninfo:\n  title: x\n")
        with self.assertRaises(coverage.CheckError):
            self.report()


class ErrorCodeGateTests(FixtureCase):
    """An error code must exist in both directions."""

    def test_emitted_code_missing_from_the_tables(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            '_failResponse( $returnJson, $success, $returnVal, 401, "owner token required" );',
            '_failResponse( $returnJson, $success, $returnVal, 401, "owner token required" );\n'
            '\t_failResponse( $returnJson, $success, $returnVal, 418, "teapot" );',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("error-code-undocumented", "418")

    def test_documented_code_that_the_module_never_emits(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace(
            "| 503 | Runner unavailable |",
            "| 451 | Unavailable for legal reasons |",
        )
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_gap("error-code-not-emitted", "451")

    def test_success_code_is_not_checked_as_an_error(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace(
            "| 400 | Validation error | 400 |",
            "| 0 | Success | 200 |\n| 400 | Validation error | 400 |",
        )
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_no_gap("error-code-not-emitted", "0")


class ActionCatalogGateTests(FixtureCase):
    """The catalog exists three times and all three must agree."""

    def test_php_and_python_catalogs_drift(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            '"command" => "StartGrindGbw",',
            '"command" => "StartGrindManual",',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("action-catalog-drift", "action_grind_start_gbw")

    def test_unavailable_entry_missing_from_python(self) -> None:
        module = self.files["tools/e64local_actions.py"].replace(
            '''    "action_fan_calibrate": {
        "risk": "actuator", "status": "unavailable", "code": 422,
        "reason": "no recovered completion signal",
    },
''',
            "",
        )
        self.rewrite("tools/e64local_actions.py", module)
        # The PHP catalog stays the source of truth, so dropping the entry from
        # the offline engine is drift, not a catalog change.
        self.assert_gap("action-catalog-drift", "action_fan_calibrate")

    def test_action_implemented_but_undocumented(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            '''\t\t"action_fan_calibrate" => array(''',
            '''\t\t"action_agsa_move" => array(
\t\t\t"risk" => "actuator",
\t\t\t"status" => "implemented",
\t\t\t"surface" => "wss",
\t\t\t"command" => "StartGrindGbw",
\t\t\t"bucket" => "grind_start",
\t\t\t"destructive" => false,
\t\t),
\t\t"action_fan_calibrate" => array(''',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        module = self.files["tools/e64local_actions.py"].replace(
            'ACTION_CATALOG: dict[str, dict[str, object]] = {',
            'ACTION_CATALOG: dict[str, dict[str, object]] = {\n'
            '    "action_agsa_move": {\n'
            '        "risk": "actuator", "status": "implemented", "surface": "wss",\n'
            '        "command": "StartGrindGbw", "bucket": "grind_start", "destructive": False,\n'
            '    },',
        )
        self.rewrite("tools/e64local_actions.py", module)
        self.assert_gap("action-implemented-undocumented", "action_agsa_move")

    def test_action_documented_but_absent(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace(
            "| `action_grind_start_gbw` | actuator | WSS `StartGrindGbw` |",
            "| `action_grind_start_gbw` | actuator | WSS `StartGrindGbw` |\n"
            "| `action_ghost` | actuator | WSS `Stop` |",
        )
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_gap("action-documented-absent", "action_ghost")

    def test_unavailable_entry_with_a_wrong_code(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            '"status" => "unavailable",\n\t\t\t"code" => 422,',
            '"status" => "unavailable",\n\t\t\t"code" => 500,',
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("action-code-mismatch", "action_fan_calibrate")

    def test_catalog_command_missing_from_the_wss_registry(self) -> None:
        registry = self.files["docs/API_REGISTRY.md"].replace(
            "| `StartGrindGbw` | `0x003f7d00` |  |  |",
            "| `StartGrindGbt` | `0x003f7d00` |  |  |",
        ).replace(
            "GrinderActionStartGrindGbw", "GrinderActionStartGrindGbt"
        )
        self.rewrite("docs/API_REGISTRY.md", registry)
        wss_doc = self.files["docs/WEBSOCKET_API.md"].replace(
            "GrinderActionStartGrindGbw", "GrinderActionStartGrindGbt"
        )
        self.rewrite("docs/WEBSOCKET_API.md", wss_doc)
        self.assert_gap("action-command-unknown", "action_grind_start_gbw")


class RateBucketGateTests(FixtureCase):
    """Every bucket a catalog entry charges must be documented."""

    def test_bucket_used_but_undocumented(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace("| `grind_start` | 6 | 30 |\n", "")
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_gap("rate-bucket-undocumented", "grind_start")

    def test_bucket_documented_but_absent(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace(
            "| `grind_start` | 6 | 30 |", "| `grind_start` | 6 | 30 |\n| `brew` | 30 | 300 |"
        )
        self.rewrite("docs/LOCAL_API.md", doc)
        self.assert_gap("rate-bucket-absent", "brew")


class WssGateTests(FixtureCase):
    """The registry is the source of truth; the protocol document describes it."""

    def test_registry_record_without_a_section(self) -> None:
        doc = self.files["docs/WEBSOCKET_API.md"].replace(
            "`RequestDriverState` asks for the driver state.",
            "The driver state is readable.",
        ).replace("    RequestDriverState\n", "")
        self.rewrite("docs/WEBSOCKET_API.md", doc)
        self.assert_gap("wss-registry-undocumented", "RequestDriverState")

    def test_registry_count_claim_mismatch(self) -> None:
        registry = self.files["docs/API_REGISTRY.md"].replace(
            "There are 1 direct records and 1 action records.",
            "There are 1 direct records and 2 action records.",
        )
        self.rewrite("docs/API_REGISTRY.md", registry)
        self.assert_gap("wss-claim-mismatch", "record counts")

    def test_inventory_names_an_unknown_command(self) -> None:
        doc = self.files["docs/WEBSOCKET_API.md"].replace(
            "    GrinderActionStartGrindGbw\n",
            "    GrinderActionStartGrindGbw\n    GrinderActionGhost\n",
        )
        self.rewrite("docs/WEBSOCKET_API.md", doc)
        self.assert_gap("wss-inventory-unknown", "GrinderActionGhost")

    def test_dispatch_label_is_accepted_only_when_explained(self) -> None:
        doc = self.files["docs/WEBSOCKET_API.md"].replace(
            "The standalone `GrinderAction` literal is the registered action dispatch type,\n"
            "not an incomplete command.\n",
            "",
        )
        self.rewrite("docs/WEBSOCKET_API.md", doc)
        self.assert_gap("wss-inventory-unknown", "GrinderAction")


class QuirkGateTests(FixtureCase):
    """A quirk must be present in the sources and stated in a document."""

    def test_quirk_missing_from_the_source(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            'define( "MAX_REQUEST_BYTES", 16384 );', 'define( "MAX_REQUEST_BYTES", 32768 );'
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        self.assert_gap("quirk-unverified", "body-limit")

    def test_quirk_missing_from_the_coverage_document(self) -> None:
        doc = self.files["docs/API_COVERAGE.md"].replace("- 1 MiB audit rotation\n", "")
        self.rewrite("docs/API_COVERAGE.md", doc)
        self.assert_gap("quirk-undocumented", "audit-rotation")

    def test_leaf_pin_missing_from_an_app(self) -> None:
        android = self.files[
            "apps/android/app/src/main/java/de/mahlkoenig/e64local/device/PinnedTrustManager.kt"
        ].replace("chain.firstOrNull()", "chain.last()")
        self.rewrite(
            "apps/android/app/src/main/java/de/mahlkoenig/e64local/device/PinnedTrustManager.kt",
            android,
        )
        self.assert_gap("quirk-unverified", "leaf-pin")


class AllowListTests(FixtureCase):
    """A known gap is reported as allowed, and a stale entry is a failure."""

    def test_known_gap_moves_to_the_allow_list(self) -> None:
        doc = self.files["docs/LOCAL_API.md"].replace("| `pong` | POST | session + token | none |\n", "")
        self.rewrite("docs/LOCAL_API.md", doc)
        entry = coverage.AllowEntry(
            kind="route-implemented-undocumented",
            record="pong",
            ticket="TICKET-1: the pong row was dropped",
        )
        with mock.patch.object(coverage, "KNOWN_GAPS", (entry,)):
            report = self.report()
        self.assertEqual([("route-implemented-undocumented", "pong")], [gap.as_key() for gap in report.allowed])
        self.assertEqual([], [gap.as_key() for gap in report.gaps])
        self.assertTrue(report.ok)

    def test_stale_allow_list_entry_is_a_failure(self) -> None:
        entry = coverage.AllowEntry(
            kind="route-implemented-undocumented",
            record="does_not_exist",
            ticket="TICKET-2: fixed elsewhere",
        )
        with mock.patch.object(coverage, "KNOWN_GAPS", (entry,)):
            report = self.report()
        self.assertEqual([], [gap.as_key() for gap in report.gaps])
        self.assertEqual(["allowlist-stale"], [gap.kind for gap in report.stale])
        self.assertFalse(report.ok)

    def test_empty_allow_list_is_the_wanted_state(self) -> None:
        self.assertEqual((), coverage.KNOWN_GAPS)


class InputErrorTests(FixtureCase):
    """A missing or unreadable input must not look like a clean run."""

    def test_missing_document_is_an_input_error(self) -> None:
        (self.root / "docs/LOCAL_API.md").unlink()
        with self.assertRaises(coverage.CheckError):
            self.report()

    def test_main_exits_two_on_a_missing_input(self) -> None:
        (self.root / "docs/API_REGISTRY.md").unlink()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(coverage.EXIT_INPUT_ERROR, coverage.main(["--root", str(self.root)]))

    def test_main_exits_one_on_a_gap(self) -> None:
        (self.root / "docs/openapi/local-api.yaml").write_text(
            "openapi: 3.1.0\ninfo:\n  title: x\npaths:\n  /rest_api/ghost:\n    post:\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(1, coverage.main(["--root", str(self.root), "--quiet"]))

    def test_broken_php_literal_is_an_input_error(self) -> None:
        php = self.files["ondevice/rest_api_dev.php"].replace(
            '$E64LOCAL_ROUTES = array(\n\t"ping",', '$E64LOCAL_ROUTES = array(\n\tping,'
        )
        self.rewrite("ondevice/rest_api_dev.php", php)
        with self.assertRaises(coverage.CheckError):
            self.report()


class ReaderTests(unittest.TestCase):
    """Small unit tests for the parsers the gates depend on."""

    def test_openapi_reader_ignores_block_scalar_content(self) -> None:
        text = (
            "openapi: 3.1.0\n"
            "paths:\n"
            "  /rest_api/ping:\n"
            "    post:\n"
            "      description: |\n"
            "        A line that starts at the wrong indent is not a path:\n"
            "        /rest_api/not_a_path\n"
            "      summary: ping\n"
            "components:\n"
            "  schemas:\n"
            "    X:\n"
            "      type: object\n"
        )
        self.assertEqual({"/rest_api/ping": ("post",)}, coverage.openapi_paths(text))

    def test_markdown_table_keeps_the_nearest_heading(self) -> None:
        text = "# Doc\n\n## 4. Route table\n\n| Route | Method |\n|---|---|\n| `a` | POST |\n\n## 5. Next\n"
        tables = coverage.markdown_tables(text)
        self.assertEqual(1, len(tables))
        self.assertEqual("4. Route table", tables[0].heading)
        self.assertEqual(("Route", "Method"), tables[0].headers)
        self.assertEqual((("`a`", "POST"),), tables[0].rows)

    def test_code_span_prefers_the_backticked_name(self) -> None:
        self.assertEqual("capabilities", coverage.code_span("[`capabilities`](#41)"))
        self.assertEqual("plain", coverage.code_span("plain"))

    def test_inventory_prefix_is_resolved_both_ways(self) -> None:
        known = {"Stop", "RequestDriverState"}
        resolved, unknown = coverage.resolve_inventory(
            ["Stop", "GrinderActionStop", "RequestDriverState", "GrinderAction", "Ghost"], known
        )
        self.assertEqual(["Stop", "Stop", "RequestDriverState"], resolved)
        self.assertEqual(["GrinderAction", "Ghost"], unknown)


class RealTreeTests(unittest.TestCase):
    """The assertion that the shipped tree is 100% documented."""

    def test_real_tree_has_no_unexpected_gaps(self) -> None:
        report = coverage.evaluate(ROOT)
        self.assertEqual(
            [],
            ["{} {}".format(*gap.as_key()) for gap in report.gaps],
            "the real tree has an undocumented or stale record",
        )
        self.assertEqual([], [gap.as_key() for gap in report.stale])
        self.assertTrue(report.ok)

    def test_real_tree_matrix_is_not_empty(self) -> None:
        # A reader that silently returns nothing would otherwise pass the gate:
        # an empty matrix must be a failure, not a clean run.
        counts = {}
        for row in coverage.evaluate(ROOT).rows:
            counts[row.kind] = counts.get(row.kind, 0) + 1
        self.assertEqual({"route": 16, "action": 33, "wss": 52}, counts)

    def test_real_tree_allow_list_is_empty(self) -> None:
        # Every entry in KNOWN_GAPS is a bug ticket.  The shipped tree has none:
        # if a gap ever becomes unavoidable, add an entry *and* a ticket.
        self.assertEqual((), coverage.KNOWN_GAPS)


if __name__ == "__main__":
    unittest.main()
