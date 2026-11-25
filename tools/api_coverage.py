#!/usr/bin/env python3
"""Prove that the local API documentation covers the shipped code.

Why this exists: the module, the prose and the OpenAPI file are edited at
different times, and each of them can drift without any test noticing.  A route
can ship with no documentation at all, a document can keep promising a route
that was removed, and the OpenAPI file can describe a method the module does
not accept.  None of those are unit-test failures, so they need a checker that
reads the documentation as data.

The checker reads the sources below, offline and with the standard library
only:

* ``ondevice/rest_api_dev.php`` - the read-only route array, the action meta
  route array, the dispatch switch inside ``restApiDev()`` and the
  ``_actionCatalog()`` literal.  This is the source of truth for our API.
* ``docs/LOCAL_API.md`` - the route tables (a row is only counted when it names
  a method, because a name without a method cannot be checked), the action
  catalog tables, the error-code tables and the rate-limit bucket table.
* ``docs/openapi/local-api.yaml`` - the ``paths:`` block, read with a small
  indentation-aware reader because PyYAML may not be installed.
* ``tools/e64local_actions.py`` - ``ACTION_CATALOG`` and its unavailable
  entries, parsed with ``ast`` so the module is never imported and no state is
  shared with the simulator.
* ``docs/API_REGISTRY.md`` and ``docs/WEBSOCKET_API.md`` - the WSS registry
  tables, the record-count claims in the prose, the sections that describe each
  record and the legacy command inventory.

It prints a coverage matrix and exits non-zero when a record is implemented but
undocumented, documented but absent from the code, or documented with a
different method or path.  ``docs/API_COVERAGE.md`` states which of these
columns is a gate and which is informational, and lists every gap that is known
and accepted.

Usage::

    python3 tools/api_coverage.py                 # matrix and gate
    python3 tools/api_coverage.py --quiet         # gaps only
    python3 tools/api_coverage.py --json          # machine-readable report

Exit codes: 0 every gate passes, 1 a gap is open, 2 an input could not be read
or parsed (a broken input must not look like a clean run).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]

PHP_MODULE = Path("ondevice/rest_api_dev.php")
ACTIONS_MODULE = Path("tools/e64local_actions.py")
SIMULATOR = Path("tools/e64ws_simulator.py")
LOCAL_API_DOC = Path("docs/LOCAL_API.md")
COVERAGE_DOC = Path("docs/API_COVERAGE.md")
OPENAPI_DOC = Path("docs/openapi/local-api.yaml")
WSS_REGISTRY_DOC = Path("docs/API_REGISTRY.md")
WSS_DOC = Path("docs/WEBSOCKET_API.md")
ANDROID_PIN = Path("apps/android/app/src/main/java/de/mahlkoenig/e64local/device/PinnedTrustManager.kt")
IOS_PIN = Path("apps/ios/GrinderCore/Sources/GrinderCore/HTTP/TLSTrust.swift")
DEPLOY_COMMANDS = Path("tools/e64root/commands.py")

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

#: Exits non-zero with this code when an input is missing or unparsable.
EXIT_INPUT_ERROR = 2


class CheckError(Exception):
    """An input file is missing, or does not have the shape the reader expects."""


# ---------------------------------------------------------------------------
# A very small PHP literal reader
#
# The module is PHP, so the route tables and the action catalog cannot be read
# with ``ast`` or ``json``.  Only the literal subset the file actually uses is
# supported: array(...), [...], "strings", 'strings', numbers, true/false/null
# and ``=>`` keys.  Anything else is a hard error: a silent partial parse would
# report a route as missing when the reader, not the code, was wrong.
# ---------------------------------------------------------------------------

_WHITESPACE = " \t\r\n"


def _php_string_end(source: str, index: int) -> int:
    """Return the index just past the quote that closes the string at *index*."""
    quote = source[index]
    index += 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    raise CheckError("unterminated PHP string literal")


def _php_skip(source: str, index: int) -> int:
    """Skip whitespace and comments."""
    while index < len(source):
        char = source[index]
        if char in _WHITESPACE:
            index += 1
            continue
        if source.startswith("//", index) or char == "#":
            newline = source.find("\n", index)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index)
            if end < 0:
                raise CheckError("unterminated PHP block comment")
            index = end + 2
            continue
        break
    return index


def _php_value(source: str, index: int) -> tuple[Any, int]:
    """Parse one literal value, returning it and the index after it."""
    index = _php_skip(source, index)
    if source.startswith("array(", index):
        return _php_array(source, index + len("array("), ")")
    if index < len(source) and source[index] == "[":
        return _php_array(source, index + 1, "]")
    if index < len(source) and source[index] == '"':
        end = _php_string_end(source, index)
        return _php_unescape(source[index + 1:end - 1]), end
    if index < len(source) and source[index] == "'":
        end = _php_string_end(source, index)
        return source[index + 1:end - 1].replace("\\'", "'").replace("\\\\", "\\"), end
    number = re.match(r"-?\d+(?:\.\d+)?", source[index:])
    if number:
        text = number.group(0)
        value: Any = float(text) if "." in text else int(text)
        return value, index + len(text)
    word = re.match(r"[A-Za-z_]+", source[index:])
    if word:
        token = word.group(0)
        if token == "true":
            return True, index + len(token)
        if token == "false":
            return False, index + len(token)
        if token == "null":
            return None, index + len(token)
    raise CheckError(
        "unsupported PHP literal at offset {}: {!r}".format(index, source[index:index + 40])
    )


def _php_unescape(text: str) -> str:
    """Undo the escape sequences PHP recognises in a double-quoted string."""
    result = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            result.append({"n": "\n", "t": "\t", "r": "\r"}.get(following, following))
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _php_array(source: str, index: int, closer: str) -> tuple[Any, int]:
    """Parse an array body up to *closer*, returning a list or a dict."""
    pairs: list[tuple[Any, Any]] = []
    plain: list[Any] = []
    index = _php_skip(source, index)
    if source.startswith(closer, index):
        return [], index + 1
    while True:
        first, index = _php_value(source, index)
        index = _php_skip(source, index)
        if source.startswith("=>", index):
            second, index = _php_value(source, index + 2)
            pairs.append((first, second))
        else:
            plain.append(first)
        index = _php_skip(source, index)
        if source.startswith(",", index):
            index = _php_skip(source, index + 1)
            if source.startswith(closer, index):
                break
            continue
        if source.startswith(closer, index):
            break
        raise CheckError(
            "unexpected PHP token at offset {}: {!r}".format(index, source[index:index + 40])
        )
    index += len(closer)
    if pairs and not plain:
        return dict(pairs), index
    if pairs:
        raise CheckError("mixed PHP array: both keyed and plain entries")
    return plain, index


def _php_literal(source: str, marker: str, path: Path) -> Any:
    """Parse the value assigned to *marker* (a ``$name`` or a call prefix).

    The marker is matched together with its ``=`` so that an earlier, unrelated
    mention (``global $E64LOCAL_ROUTES, $E64LOCAL_ACTION_META_ROUTES;``) cannot
    hijack the parse.
    """
    match = re.search(re.escape(marker) + r"\s*=", source)
    if match is None:
        raise CheckError("{}: marker not found: {}".format(path, marker))
    value, _ = _php_value(source, match.end())
    return value


def _php_brace_block(source: str, open_index: int) -> str:
    """Return the text between the brace at *open_index* and its match."""
    if source[open_index] != "{":
        raise CheckError("internal error: expected an opening brace")
    depth = 0
    index = open_index
    while index < len(source):
        if source.startswith("//", index) or source[index] == "#":
            newline = source.find("\n", index)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index)
            index = len(source) if end < 0 else end + 2
            continue
        char = source[index]
        if char in "\"'":
            index = _php_string_end(source, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_index + 1:index]
        index += 1
    raise CheckError("unbalanced braces in the PHP module")


def _php_argument_list(source: str, open_index: int) -> list[str]:
    """Split the call arguments that start at the parenthesis *open_index*."""
    if source[open_index] != "(":
        raise CheckError("internal error: expected an opening parenthesis")
    arguments: list[str] = []
    depth = 0
    start = open_index + 1
    index = open_index
    while index < len(source):
        char = source[index]
        if char in "\"'":
            index = _php_string_end(source, index)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                tail = source[start:index].strip()
                if tail:
                    arguments.append(tail)
                return arguments
        elif char == "," and depth == 1:
            arguments.append(source[start:index].strip())
            start = index + 1
        index += 1
    raise CheckError("unterminated PHP call")


def _php_switch_cases(source: str, function_name: str, switch_text: str) -> tuple[str, ...]:
    """Return the ``case "..."`` labels of one switch inside *function_name*."""
    function = source.find("function " + function_name + "(")
    if function < 0:
        raise CheckError("PHP function not found: " + function_name)
    switch = source.find(switch_text, function)
    if switch < 0:
        raise CheckError("switch not found in {}: {}".format(function_name, switch_text))
    body = _php_brace_block(source, source.index("{", switch))
    return tuple(re.findall(r'case\s+"([^"]+)"\s*:', body))


# ---------------------------------------------------------------------------
# Markdown tables
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Table:
    """One Markdown table with the heading it appears under."""

    heading: str
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


_SEPARATOR = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


def markdown_tables(text: str) -> list[Table]:
    """Collect every pipe table in *text*, tagged with the nearest heading."""
    lines = text.splitlines()
    heading = "(no heading)"
    tables: list[Table] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            index += 1
            continue
        if line.lstrip().startswith("|") and index + 1 < len(lines) and _SEPARATOR.match(lines[index + 1]):
            headers = _cells(line)
            rows: list[tuple[str, ...]] = []
            index += 2
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                rows.append(_cells(lines[index]))
                index += 1
            tables.append(Table(heading=heading, headers=headers, rows=tuple(rows)))
            continue
        index += 1
    return tables


def _cells(line: str) -> tuple[str, ...]:
    return tuple(cell.strip() for cell in line.strip().strip("|").split("|"))


def code_span(cell: str) -> str:
    """Return the first `backticked` token in a table cell, else the cell."""
    match = re.search(r"`([^`]+)`", cell)
    return match.group(1).strip() if match else cell.strip()


def _normalised_headers(table: Table) -> tuple[str, ...]:
    return tuple(header.strip().strip("`").lower() for header in table.headers)


# ---------------------------------------------------------------------------
# Source readers
# ---------------------------------------------------------------------------


def _read(root: Path, relative: Path) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise CheckError("missing input file: {}".format(relative)) from exc
    except OSError as exc:
        raise CheckError("cannot read {}: {}".format(relative, exc)) from exc


def php_route_array(source: str, marker: str) -> tuple[str, ...]:
    """Read a flat ``array( "a", "b" )`` of route names."""
    value = _php_literal(source, marker, PHP_MODULE)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CheckError("{} is not a flat string array".format(marker))
    return tuple(value)


def php_catalog(source: str) -> dict[str, dict[str, Any]]:
    """Read the ``$catalog = array( ... )`` literal inside ``_actionCatalog()``."""
    function = source.find("function _actionCatalog(")
    if function < 0:
        raise CheckError("PHP function not found: _actionCatalog")
    body = _php_brace_block(source, source.index("{", function))
    assignment = re.search(r"\$catalog\s*=\s*array\(", body)
    if assignment is None:
        raise CheckError("_actionCatalog() does not assign $catalog a literal array")
    value, _ = _php_value(body, assignment.end() - len("array("))
    if not isinstance(value, dict):
        raise CheckError("_actionCatalog() does not return a literal array")
    catalog: dict[str, dict[str, Any]] = {}
    for name, entry in value.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise CheckError("unexpected action catalog entry: {!r}".format(name))
        catalog[name] = entry
    return catalog


def php_emitted_codes(source: str) -> tuple[frozenset[int], frozenset[int]]:
    """Return (tight, loose) sets of error codes the module can emit.

    *tight* is what the module passes to ``_failResponse()`` as an integer and
    what it assigns to a variable named ``...code``.  *loose* is every 3-digit
    literal in the 400-599 range anywhere in the file, which is used only for
    the "documented but never emitted" direction: it can over-collect (the
    file also uses 500 as a page-size default), never under-collect.
    """
    tight: set[int] = set()
    for match in re.finditer(r"_failResponse\s*\(", source):
        arguments = _php_argument_list(source, match.end() - 1)
        if len(arguments) >= 4 and re.fullmatch(r"\d{3}", arguments[3]):
            tight.add(int(arguments[3]))
    for match in re.finditer(r"\$[A-Za-z_]*[Cc]ode\s*=\s*(\d{3})\s*;", source):
        tight.add(int(match.group(1)))
    loose = {int(match.group(0)) for match in re.finditer(r"(?<![\d.])([45]\d{2})(?![\d.])", source)}
    return frozenset(tight), frozenset(loose | tight)


def python_action_catalog(source: str) -> dict[str, dict[str, Any]]:
    """Read ``ACTION_CATALOG`` from the offline engine without importing it."""
    tree = ast.parse(source)
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and target.id == "ACTION_CATALOG" and value is not None:
            catalogue = ast.literal_eval(value)
            if not isinstance(catalogue, dict):
                raise CheckError("ACTION_CATALOG is not a dict literal")
            return catalogue
    raise CheckError("ACTION_CATALOG is not a module-level literal assignment")


def python_meta_routes(source: str) -> tuple[str, ...]:
    """Read ``ACTION_META_ROUTES`` from the offline engine."""
    tree = ast.parse(source)
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and target.id == "ACTION_META_ROUTES" and value is not None:
            routes = ast.literal_eval(value)
            if not isinstance(routes, (tuple, list)):
                raise CheckError("ACTION_META_ROUTES is not a literal sequence")
            return tuple(str(route) for route in routes)
    raise CheckError("ACTION_META_ROUTES is not a module-level literal assignment")


def simulator_surface(
    source: str, root: Path
) -> tuple[tuple[str, ...], tuple[str, ...], frozenset[str], frozenset[str]]:
    """Return (local routes, action routes, WSS suffixes, direct WSS types).

    ``SimulatedLocalApi.ACTION_ROUTES`` is assigned the imported constant
    ``ACTION_META_ROUTES`` rather than a literal, so the import is checked and
    the value is taken from the engine that the simulator imports.
    """
    tree = ast.parse(source)
    suffixes: frozenset[str] | None = None
    for node in tree.body:
        target = node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None
        if isinstance(target, ast.Name) and target.id == "ACTION_SUFFIXES":
            call = node.value
            if isinstance(call, ast.Call) and getattr(call.func, "id", "") == "frozenset":
                suffixes = frozenset(ast.literal_eval(call.args[0]))
    if suffixes is None:
        raise CheckError("ACTION_SUFFIXES is not a frozenset literal in the simulator")

    local_routes: tuple[str, ...] | None = None
    action_routes: tuple[str, ...] | None = None
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "SimulatedLocalApi":
            continue
        for statement in node.body:
            target: ast.expr | None = None
            value: ast.expr | None = None
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target, value = statement.targets[0], statement.value
            elif isinstance(statement, ast.AnnAssign):
                target, value = statement.target, statement.value
            if not isinstance(target, ast.Name) or value is None:
                continue
            if target.id == "ROUTES":
                local_routes = tuple(str(route) for route in ast.literal_eval(value))
            elif target.id == "ACTION_ROUTES":
                if isinstance(value, ast.Name):
                    action_routes = _resolved_import(source, value.id, root)
                else:
                    action_routes = tuple(str(route) for route in ast.literal_eval(value))
    if local_routes is None:
        raise CheckError("SimulatedLocalApi.ROUTES was not found")
    if action_routes is None:
        raise CheckError("SimulatedLocalApi.ACTION_ROUTES was not found")
    direct_types = frozenset(re.findall(r'command_type == "([A-Za-z0-9]+)"', source))
    return local_routes, action_routes, suffixes, direct_types


def _resolved_import(source: str, name: str, root: Path) -> tuple[str, ...]:
    """Resolve a name the simulator imports from the action engine."""
    if not re.search(r"from\s+\S*e64local_actions\s+import\s*\([^)]*\b" + re.escape(name) + r"\b", source, re.S):
        raise CheckError(
            "{} is not imported from e64local_actions; cannot resolve it".format(name)
        )
    return python_meta_routes(_read(root, ACTIONS_MODULE))


def openapi_paths(text: str) -> dict[str, tuple[str, ...]]:
    """Read ``paths:`` -> {path: (methods,)} with an indentation-aware reader."""
    paths: dict[str, tuple[str, ...]] = {}
    lines = text.splitlines()
    in_paths = False
    paths_indent = 0
    current: str | None = None
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if not in_paths:
            if stripped == "paths:":
                in_paths = True
                paths_indent = indent
            continue
        if indent <= paths_indent:
            break
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].rstrip()
        if indent == paths_indent + 2 and stripped.startswith("/"):
            current = stripped.rstrip(":").strip().strip('"').strip("'")
            paths.setdefault(current, ())
            continue
        if indent == paths_indent + 4 and current is not None:
            method = stripped.split(":", 1)[0].strip().strip('"').strip("'").lower()
            if method in HTTP_METHODS and ":" in stripped:
                paths[current] = paths[current] + (method,)
    if not in_paths:
        raise CheckError("the OpenAPI document has no paths: block")
    if not paths:
        raise CheckError("the OpenAPI document has an empty paths: block")
    return paths


def wss_registry(text: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[int, int] | None]:
    """Return (direct records, action suffixes, (claimed direct, claimed action))."""
    direct: tuple[str, ...] = ()
    actions: list[str] = []
    for table in markdown_tables(text):
        headers = _normalised_headers(table)
        if headers[:2] == ("type", "log"):
            direct = tuple(code_span(row[0]) for row in table.rows if row and code_span(row[0]))
        elif headers[:4] == ("suffix", "callback", "suffix", "callback"):
            for row in table.rows:
                for column in (0, 2):
                    if column < len(row):
                        name = code_span(row[column])
                        if name and name != "suffix":
                            actions.append(name)
    claim = re.search(r"There are\s+(\d+)\s+direct records and\s+(\d+)\s+action records", text)
    claimed = (int(claim.group(1)), int(claim.group(2))) if claim else None
    return direct, tuple(actions), claimed


def markdown_sections(text: str) -> list[tuple[str, str]]:
    """Split a Markdown document into (level-2 heading, body) pairs."""
    sections: list[tuple[str, str]] = []
    heading = "(preamble)"
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            sections.append((heading, "\n".join(body)))
            heading = line[3:].strip()
            body = []
            continue
        body.append(line)
    sections.append((heading, "\n".join(body)))
    return sections


def section_body(text: str, heading: str) -> str:
    """Return the body of the level-2 section whose heading contains *heading*."""
    for name, body in markdown_sections(text):
        if heading.lower() in name.lower():
            return body
    raise CheckError("section not found in the WebSocket document: " + heading)


def wss_mentions(text: str, names: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Map each name to the level-2 sections of *text* that name it exactly.

    The protocol document predates the registry and names an action either by
    its bare suffix or as ``GrinderAction<suffix>``, so both spellings count as
    a mention.  The match is still anchoring on both sides, so ``Stop`` is not
    satisfied by ``StopAgsa``.
    """
    sections = markdown_sections(text)
    mentions: dict[str, tuple[str, ...]] = {}
    for name in names:
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:GrinderAction)?" + re.escape(name) + r"(?![A-Za-z0-9_])"
        )
        mentions[name] = tuple(heading for heading, body in sections if pattern.search(body))
    return mentions


def wss_inventory(text: str) -> tuple[str, ...]:
    """Read the indented legacy command inventory."""
    body = section_body(text, "Exact command inventory")
    names = []
    for line in body.splitlines():
        match = re.fullmatch(r" {4}([A-Za-z][A-Za-z0-9]*)", line)
        if match:
            names.append(match.group(1))
    return tuple(names)


# ---------------------------------------------------------------------------
# The gates: normative claims that must hold in both code and documentation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """A pattern that must appear in one file."""

    path: Path
    pattern: str


@dataclass(frozen=True)
class Quirk:
    """One non-obvious behaviour that must be provable and documented."""

    key: str
    summary: str
    doc: tuple[Evidence, ...]
    source: tuple[Evidence, ...]


QUIRKS: tuple[Quirk, ...] = (
    Quirk(
        key="dev-gate",
        summary="the module refuses to run unless /etc/issue starts with development",
        doc=(
            Evidence(LOCAL_API_DOC, r"`/etc/issue`"),
            Evidence(COVERAGE_DOC, r"dev gate on `/etc/issue`"),
        ),
        source=(
            Evidence(PHP_MODULE, r'function_exists\(\s*"isDev"\s*\)\s*\|\|\s*!isDev\(\)'),
            Evidence(PHP_MODULE, r"/etc/issue"),
        ),
    ),
    Quirk(
        key="dual-auth",
        summary="a vendor REST session plus the owner token file are both required",
        doc=(
            Evidence(LOCAL_API_DOC, r"X-E64-Local-Token"),
            Evidence(COVERAGE_DOC, r"vendor session plus owner token"),
        ),
        source=(
            Evidence(PHP_MODULE, r"HTTP_X_E64_LOCAL_TOKEN"),
            Evidence(PHP_MODULE, r'E64LOCAL_TOKEN_FILE",\s*"/db/e64local/token"'),
        ),
    ),
    Quirk(
        key="body-limit",
        summary="a request body over 16384 bytes is refused with 413",
        doc=(
            Evidence(LOCAL_API_DOC, r"16,384 bytes"),
            Evidence(COVERAGE_DOC, r"16 KiB body limit"),
        ),
        source=(
            Evidence(PHP_MODULE, r'MAX_REQUEST_BYTES",\s*16384'),
            Evidence(PHP_MODULE, r"exceeded|body too large"),
        ),
    ),
    Quirk(
        key="row-cap",
        summary="a log page cannot exceed 5000 rows",
        doc=(
            Evidence(LOCAL_API_DOC, r"5,000"),
            Evidence(COVERAGE_DOC, r"5000-row page cap"),
        ),
        source=(
            Evidence(PHP_MODULE, r'MAX_ROWS_GRIND_LOG",\s*5000'),
            Evidence(PHP_MODULE, r'MAX_ROWS_SERVICE_LOG",\s*5000'),
            Evidence(PHP_MODULE, r'MAX_ROWS_ALERT_LOG",\s*5000'),
        ),
    ),
    Quirk(
        key="action-names-not-paths",
        summary="a bare POST to an action identifier is 404, or 403 for a boundary name",
        doc=(
            Evidence(LOCAL_API_DOC, r"not HTTP paths"),
            Evidence(COVERAGE_DOC, r"`action_\*` names are not paths"),
        ),
        source=(
            Evidence(PHP_MODULE, r"action identifiers are not HTTP paths; use action_prepare"),
            Evidence(PHP_MODULE, r"_actionIsBoundaryName\( \$requestUri \)"),
        ),
    ),
    Quirk(
        key="unavailable-422",
        summary="an unavailable catalog entry is refused with 422 and its reason",
        doc=(
            Evidence(LOCAL_API_DOC, r"\| `action_fan_calibrate` \| 422 \|"),
            Evidence(COVERAGE_DOC, r"422 for unavailable actions"),
        ),
        source=(Evidence(PHP_MODULE, r'"code" => 422'),),
    ),
    Quirk(
        key="runner-503",
        summary="without the sudoers rule or the runner, every action is 503",
        doc=(
            Evidence(LOCAL_API_DOC, r"/etc/sudoers.d/e64local"),
            Evidence(COVERAGE_DOC, r"503 when the runner cannot start"),
        ),
        # The module never reads the sudoers file: it runs ``sudo -n`` and
        # reports 503 when the helper does not return a result.  The rule itself
        # is written by the deploy command.
        source=(
            Evidence(PHP_MODULE, r"the action runner did not return a result"),
            Evidence(PHP_MODULE, r'escapeshellarg\( \$sudo \) \. " -n "'),
            Evidence(DEPLOY_COMMANDS, r'API_SUDOERS_FILE = "/etc/sudoers\.d/e64local"'),
        ),
    ),
    Quirk(
        key="boot-id-409",
        summary="a prepared action does not survive a reboot: the boot id change is 409",
        doc=(
            Evidence(LOCAL_API_DOC, r"boot id"),
            Evidence(COVERAGE_DOC, r"409 on boot-id change"),
        ),
        source=(
            Evidence(PHP_MODULE, r'BOOT_ID_FILE",\s*"/proc/sys/kernel/random/boot_id"'),
            Evidence(PHP_MODULE, r"the device has rebooted since this action was prepared"),
        ),
    ),
    Quirk(
        key="monotonic-buckets",
        summary="rate-limit windows use a monotonic clock, so a wall-clock step cannot reset them",
        doc=(
            Evidence(LOCAL_API_DOC, r"monotonic milliseconds"),
            Evidence(COVERAGE_DOC, r"monotonic rate buckets"),
        ),
        source=(Evidence(PHP_MODULE, r"hrtime\(\s*true\s*\)"),),
    ),
    Quirk(
        key="audit-rotation",
        summary="the audit log rotates at 1 MiB and keeps three files",
        doc=(
            Evidence(LOCAL_API_DOC, r"1 MiB"),
            Evidence(COVERAGE_DOC, r"1 MiB audit rotation"),
        ),
        source=(
            Evidence(PHP_MODULE, r'AUDIT_MAX_BYTES",\s*1048576'),
            Evidence(PHP_MODULE, r'AUDIT_KEEP",\s*3'),
        ),
    ),
    Quirk(
        key="leaf-pin",
        summary="both apps pin the leaf certificate, not a CA",
        doc=(
            Evidence(COVERAGE_DOC, r"leaf-certificate pin"),
            Evidence(COVERAGE_DOC, r"PinnedTrustManager\.kt"),
            Evidence(COVERAGE_DOC, r"TLSTrust\.swift"),
        ),
        source=(
            Evidence(ANDROID_PIN, r"chain\.firstOrNull\(\)"),
            Evidence(ANDROID_PIN, r'"SHA-256"'),
            Evidence(IOS_PIN, r"pinnedLeaf\(sha256"),
            Evidence(IOS_PIN, r"leaf certificate"),
        ),
    ),
)


# ---------------------------------------------------------------------------
# The snapshot and the analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Snapshot:
    """Everything the checker read, already parsed."""

    php_routes: tuple[str, ...]
    php_meta_routes: tuple[str, ...]
    php_dispatch: tuple[str, ...]
    php_meta_dispatch: tuple[str, ...]
    php_catalog: dict[str, dict[str, Any]]
    php_codes_tight: frozenset[int]
    php_codes_loose: frozenset[int]
    php_rates: dict[str, Any]
    py_catalog: dict[str, dict[str, Any]]
    py_meta_routes: tuple[str, ...]
    sim_routes: tuple[str, ...]
    sim_action_routes: tuple[str, ...]
    sim_suffixes: frozenset[str]
    sim_direct_types: frozenset[str]
    doc_routes: dict[str, tuple[str, str]]
    doc_actions: dict[str, str]
    doc_unavailable: dict[str, str]
    doc_codes: dict[int, str]
    doc_rates: dict[str, str]
    openapi: dict[str, tuple[str, ...]]
    wss_direct: tuple[str, ...]
    wss_actions: tuple[str, ...]
    wss_claim: tuple[int, int] | None
    wss_mentions: dict[str, tuple[str, ...]]
    wss_inventory: tuple[str, ...]
    wss_dispatch_label_explained: bool


def load_snapshot(root: Path) -> Snapshot:
    """Read and parse every input below *root*."""
    php = _read(root, PHP_MODULE)
    actions = _read(root, ACTIONS_MODULE)
    simulator = _read(root, SIMULATOR)
    local_api = _read(root, LOCAL_API_DOC)
    openapi = _read(root, OPENAPI_DOC)
    registry = _read(root, WSS_REGISTRY_DOC)
    wss_doc = _read(root, WSS_DOC)
    _read(root, COVERAGE_DOC)  # required: the quirks gate documents itself there

    tables = markdown_tables(local_api)
    doc_routes: dict[str, tuple[str, str]] = {}
    doc_actions: dict[str, str] = {}
    doc_unavailable: dict[str, str] = {}
    doc_codes: dict[int, str] = {}
    doc_rates: dict[str, str] = {}
    for table in tables:
        headers = _normalised_headers(table)
        if headers[:2] == ("route", "method"):
            for row in table.rows:
                name = code_span(row[0]) if row else ""
                if name:
                    doc_routes.setdefault(name, (code_span(row[1]).upper() if len(row) > 1 else "", table.heading))
        elif headers[:2] == ("route", "risk"):
            for row in table.rows:
                name = code_span(row[0]) if row else ""
                if name:
                    doc_actions.setdefault(name, table.heading)
        elif headers[:2] == ("route", "code"):
            for row in table.rows:
                name = code_span(row[0]) if row else ""
                code = row[1].strip() if len(row) > 1 else ""
                if name and code.isdigit():
                    doc_unavailable.setdefault(name, table.heading)
        elif headers[:1] in (("errorcode",), ("code",)):
            for row in table.rows:
                cell = row[0].strip().strip("`").strip() if row else ""
                if cell.isdigit():
                    doc_codes.setdefault(int(cell), table.heading)
        elif headers[:1] == ("bucket",):
            for row in table.rows:
                name = code_span(row[0]) if row else ""
                if name:
                    doc_rates.setdefault(name, table.heading)

    direct, action_suffixes, claim = wss_registry(registry)
    tight, loose = php_emitted_codes(php)
    sim_routes, sim_action_routes, sim_suffixes, sim_direct_types = simulator_surface(simulator, root)
    all_suffixes = direct + action_suffixes
    return Snapshot(
        php_routes=php_route_array(php, "$E64LOCAL_ROUTES"),
        php_meta_routes=php_route_array(php, "$E64LOCAL_ACTION_META_ROUTES"),
        php_dispatch=_php_switch_cases(php, "restApiDev", "switch ( $requestUri )"),
        php_meta_dispatch=_php_switch_cases(php, "_handleActionRoute", "switch ( $route )"),
        php_catalog=php_catalog(php),
        php_codes_tight=tight,
        php_codes_loose=loose,
        php_rates=_php_literal(php, "$E64LOCAL_ACTION_DEFAULT_RATES", PHP_MODULE),
        py_catalog=python_action_catalog(actions),
        py_meta_routes=python_meta_routes(actions),
        sim_routes=sim_routes,
        sim_action_routes=sim_action_routes,
        sim_suffixes=sim_suffixes,
        sim_direct_types=sim_direct_types,
        doc_routes=doc_routes,
        doc_actions=doc_actions,
        doc_unavailable=doc_unavailable,
        doc_codes=doc_codes,
        doc_rates=doc_rates,
        openapi=openapi_paths(openapi),
        wss_direct=direct,
        wss_actions=action_suffixes,
        wss_claim=claim,
        wss_mentions=wss_mentions(wss_doc, all_suffixes),
        wss_inventory=wss_inventory(wss_doc),
        # The inventory lists the bare ``GrinderAction`` label as well.  That is
        # the dispatch type, not a record; it is only accepted when the document
        # says so, so a silently missing record cannot hide behind the exception.
        wss_dispatch_label_explained=bool(
            re.search(r"standalone `GrinderAction` literal is the registered action dispatch type", wss_doc)
        ),
    )


@dataclass(frozen=True)
class Row:
    """One coverage-matrix line."""

    kind: str
    record: str
    implemented: str
    documented: str
    openapi: str
    simulator: str


@dataclass(frozen=True)
class Gap:
    """One failed gate."""

    kind: str
    record: str
    detail: str

    def as_key(self) -> tuple[str, str]:
        return (self.kind, self.record)


@dataclass(frozen=True)
class AllowEntry:
    """A known gap.  Every entry is a bug ticket, not a waiver of the gate."""

    kind: str
    record: str
    ticket: str


#: Known gaps that are not fixed in this change.
#:
#: Each entry is a bug ticket.  The fix is to remove the cause in the code or
#: the document; the entry must be deleted in that same change, because a list
#: that only grows turns the gate into decoration.  The empty tuple is the
#: wanted state, and ``tools/test_api_coverage.py`` asserts that it is empty.
KNOWN_GAPS: tuple[AllowEntry, ...] = ()


@dataclass(frozen=True)
class Report:
    rows: tuple[Row, ...]
    gaps: tuple[Gap, ...]
    allowed: tuple[Gap, ...]
    stale: tuple[Gap, ...]

    @property
    def ok(self) -> bool:
        return not self.gaps and not self.stale


def analyse(snapshot: Snapshot) -> tuple[list[Row], list[Gap]]:
    """Build the matrix and the gap list."""
    rows: list[Row] = []
    gaps: list[Gap] = []
    _check_routes(snapshot, rows, gaps)
    _check_actions(snapshot, rows, gaps)
    _check_error_codes(snapshot, gaps)
    _check_rate_buckets(snapshot, gaps)
    _check_wss(snapshot, rows, gaps)
    return rows, gaps


def _check_routes(snapshot: Snapshot, rows: list[Row], gaps: list[Gap]) -> None:
    """Gate the dispatch switch against the docs, the OpenAPI file and the simulator."""
    dispatched = set(snapshot.php_dispatch)
    advertised = set(snapshot.php_routes) | set(snapshot.php_meta_routes)
    simulated = set(snapshot.sim_routes) | set(snapshot.sim_action_routes)

    for name in sorted(advertised | set(snapshot.doc_routes)):
        implemented = name in dispatched
        documented = snapshot.doc_routes.get(name)
        openapi = snapshot.openapi.get("/rest_api/" + name, ())
        rows.append(
            Row(
                kind="route",
                record=name,
                implemented="yes" if implemented else "no",
                documented=documented[0] if documented else "-",
                openapi=openapi[0].upper() if openapi else "-",
                simulator="yes" if name in simulated else "no",
            )
        )
        if implemented and documented is None:
            gaps.append(
                Gap(
                    "route-implemented-undocumented",
                    name,
                    "dispatched by restApiDev() but no Route+Method row in docs/LOCAL_API.md",
                )
            )
        if documented is not None and not implemented:
            gaps.append(
                Gap(
                    "route-documented-absent",
                    name,
                    "documented under '{}' but not dispatched by restApiDev()".format(documented[1]),
                )
            )
        if documented is not None and documented[0] and documented[0] != "POST":
            gaps.append(
                Gap(
                    "route-method-mismatch",
                    name,
                    "docs say {} but every implemented route is POST".format(documented[0]),
                )
            )
        if implemented and not openapi:
            gaps.append(
                Gap(
                    "route-missing-openapi",
                    name,
                    "no /rest_api/{} path in docs/openapi/local-api.yaml".format(name),
                )
            )
        if openapi and "post" not in openapi:
            gaps.append(
                Gap(
                    "openapi-method-mismatch",
                    name,
                    "OpenAPI declares {} but the module only dispatches POST".format(
                        ",".join(openapi)
                    ),
                )
            )
        if implemented and name not in simulated:
            gaps.append(
                Gap("route-missing-simulator", name, "not in SimulatedLocalApi.ROUTES or ACTION_ROUTES")
            )

    declared = {"/rest_api/" + name for name in advertised}
    for path in sorted(set(snapshot.openapi) - declared):
        gaps.append(Gap("openapi-extra-path", path, "declared in the OpenAPI file but not a route"))

    for name in sorted(set(snapshot.php_routes) - dispatched):
        gaps.append(
            Gap("route-advertised-not-dispatched", name, "listed in $E64LOCAL_ROUTES but no case handles it")
        )
    for name in sorted(dispatched - advertised):
        gaps.append(
            Gap(
                "route-dispatched-not-advertised",
                name,
                "dispatched but in neither route array, so capabilities never lists it",
            )
        )

    if set(snapshot.php_meta_routes) != set(snapshot.py_meta_routes):
        gaps.append(Gap("route-meta-drift", "action_*", "the PHP and Python meta route lists differ"))
    for name in sorted(set(snapshot.php_meta_dispatch) - set(snapshot.php_meta_routes)):
        gaps.append(
            Gap("route-meta-unreachable", name, "_handleActionRoute handles it but nothing advertises it")
        )
    for name in sorted(set(snapshot.php_meta_routes) - set(snapshot.php_meta_dispatch)):
        gaps.append(
            Gap("route-meta-not-routed", name, "advertised but _handleActionRoute does not dispatch it")
        )


def _check_actions(snapshot: Snapshot, rows: list[Row], gaps: list[Gap]) -> None:
    """Gate the two catalogs and the catalog tables against each other."""
    every = (
        set(snapshot.php_catalog)
        | set(snapshot.py_catalog)
        | set(snapshot.doc_actions)
        | set(snapshot.doc_unavailable)
    )
    registry = set(snapshot.wss_direct) | set(snapshot.wss_actions)
    for name in sorted(every):
        php_entry = snapshot.php_catalog.get(name)
        py_entry = snapshot.py_catalog.get(name)
        documented = name in snapshot.doc_actions or name in snapshot.doc_unavailable
        implemented = bool(php_entry and php_entry.get("status") == "implemented")
        rows.append(
            Row(
                kind="action",
                record=name,
                implemented="yes" if implemented else "no",
                documented="catalog" if documented else "-",
                openapi="-",
                simulator="yes" if py_entry else "no",
            )
        )
        if php_entry is None:
            gaps.append(
                Gap("action-documented-absent", name, "documented but absent from _actionCatalog()")
            )
            continue
        if py_entry is None:
            gaps.append(
                Gap("action-catalog-drift", name, "in the PHP catalog but not in ACTION_CATALOG")
            )
            continue
        for field in ("status", "risk", "surface", "command"):
            if php_entry.get(field) != py_entry.get(field):
                gaps.append(
                    Gap(
                        "action-catalog-drift",
                        name,
                        "{} differs: php={!r} python={!r}".format(
                            field, php_entry.get(field), py_entry.get(field)
                        ),
                    )
                )
        if implemented and not documented:
            gaps.append(
                Gap(
                    "action-implemented-undocumented",
                    name,
                    "implemented in the catalog but no row in the docs/LOCAL_API.md catalog tables",
                )
            )
        if not implemented and name not in snapshot.doc_unavailable:
            gaps.append(
                Gap(
                    "action-unavailable-undocumented",
                    name,
                    "unavailable in the catalog but not in the unavailable table",
                )
            )
        if implemented and name in snapshot.doc_unavailable:
            gaps.append(
                Gap("action-status-mismatch", name, "implemented in the catalog but listed as unavailable")
            )
        php_code = php_entry.get("code")
        if php_entry.get("status") == "unavailable" and php_code != 422:
            gaps.append(
                Gap(
                    "action-code-mismatch",
                    name,
                    "unavailable entry does not refuse with 422 (php code={!r})".format(php_code),
                )
            )
        command = php_entry.get("command")
        if php_entry.get("surface") == "wss" and command and command not in registry:
            gaps.append(
                Gap(
                    "action-command-unknown",
                    name,
                    "WSS command {!r} is not in docs/API_REGISTRY.md".format(command),
                )
            )

    for name in sorted(set(snapshot.py_catalog) - set(snapshot.php_catalog)):
        gaps.append(Gap("action-catalog-drift", name, "in ACTION_CATALOG but not in _actionCatalog()"))


def _check_error_codes(snapshot: Snapshot, gaps: list[Gap]) -> None:
    """Every emitted code must be documented, and every documented code emitted."""
    documented = set(snapshot.doc_codes)
    for code in sorted(snapshot.php_codes_tight - documented):
        gaps.append(
            Gap(
                "error-code-undocumented",
                str(code),
                "emitted by _failResponse() but absent from every error-code table",
            )
        )
    # 0 is the success code, never a failure literal, so only 4xx/5xx are
    # checked in this direction.
    for code in sorted(code for code in documented - set(snapshot.php_codes_loose) if code >= 400):
        gaps.append(
            Gap("error-code-not-emitted", str(code), "documented but the literal never appears in the module")
        )


def _check_rate_buckets(snapshot: Snapshot, gaps: list[Gap]) -> None:
    """A bucket a catalog entry charges must be in the documented rate table."""
    charged = {
        str(entry.get("bucket"))
        for entry in snapshot.php_catalog.values()
        if entry.get("bucket")
    }
    for bucket in sorted(charged - set(snapshot.doc_rates)):
        gaps.append(
            Gap(
                "rate-bucket-undocumented",
                bucket,
                "a catalog entry charges this bucket but the rate table omits it",
            )
        )
    for bucket in sorted(set(snapshot.doc_rates) - set(snapshot.php_rates) - {"execute"}):
        gaps.append(
            Gap("rate-bucket-absent", bucket, "documented bucket is not in $E64LOCAL_ACTION_DEFAULT_RATES")
        )


def _check_wss(snapshot: Snapshot, rows: list[Row], gaps: list[Gap]) -> None:
    """Gate the registry against the protocol document and the inventory."""
    known = set(snapshot.wss_direct) | set(snapshot.wss_actions)
    for name in sorted(known):
        mention = snapshot.wss_mentions.get(name, ())
        simulated = name in snapshot.sim_suffixes or name in snapshot.sim_direct_types
        rows.append(
            Row(
                kind="wss",
                record=name,
                implemented="registry",
                documented=mention[0] if mention else "-",
                openapi="-",
                simulator="yes" if simulated else "no",
            )
        )
        if not mention:
            gaps.append(
                Gap(
                    "wss-registry-undocumented",
                    name,
                    "in docs/API_REGISTRY.md but no section of docs/WEBSOCKET_API.md names it",
                )
            )
    claim = (len(snapshot.wss_direct), len(snapshot.wss_actions))
    if snapshot.wss_claim != claim:
        gaps.append(
            Gap(
                "wss-claim-mismatch",
                "record counts",
                "the registry prose claims {} but the tables list {}".format(snapshot.wss_claim, claim),
            )
        )
    _, unknown = resolve_inventory(snapshot.wss_inventory, known)
    for name in unknown:
        if name == "GrinderAction" and snapshot.wss_dispatch_label_explained:
            # The document states that this label is the dispatch type, not a
            # record.  When that sentence disappears the label is a gap again.
            continue
        gaps.append(
            Gap("wss-inventory-unknown", name, "named in the legacy inventory but not in the registry")
        )


def resolve_inventory(inventory: Sequence[str], known: set[str]) -> tuple[list[str], list[str]]:
    """Map legacy ``GrinderActionX`` labels onto registry records."""
    resolved: list[str] = []
    unknown: list[str] = []
    for name in inventory:
        if name in known:
            resolved.append(name)
            continue
        if name.startswith("GrinderAction") and name[len("GrinderAction"):] in known:
            resolved.append(name[len("GrinderAction"):])
            continue
        unknown.append(name)
    return resolved, unknown


def check_quirks(root: Path) -> list[Gap]:
    """Verify every quirk is both present in the sources and stated in a doc.

    Source patterns are case-sensitive because they match code.  Document
    patterns are case-insensitive because a heading capitalises the first word.
    """
    gaps: list[Gap] = []
    for quirk in QUIRKS:
        for evidence in quirk.source:
            text = _read_or_empty(root, evidence.path)
            if not re.search(evidence.pattern, text):
                gaps.append(Gap("quirk-unverified", quirk.key, "{} does not match {!r}: {}".format(evidence.path, evidence.pattern, quirk.summary)))
        for evidence in quirk.doc:
            text = _read_or_empty(root, evidence.path)
            if not re.search(evidence.pattern, text, re.IGNORECASE):
                gaps.append(Gap("quirk-undocumented", quirk.key, "{} does not state {!r}".format(evidence.path, evidence.pattern)))
    return gaps


def _read_or_empty(root: Path, relative: Path) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError:
        return ""


def evaluate(root: Path = ROOT) -> Report:
    """Run every gate against *root* and apply the known-gap list."""
    snapshot = load_snapshot(root)
    rows, gaps = analyse(snapshot)
    gaps.extend(check_quirks(root))
    allowed: list[Gap] = []
    unexpected: list[Gap] = []
    allow_keys = {(entry.kind, entry.record) for entry in KNOWN_GAPS}
    for gap in gaps:
        if gap.as_key() in allow_keys:
            allowed.append(gap)
        else:
            unexpected.append(gap)
    reported = {gap.as_key() for gap in gaps}
    stale = [
        Gap("allowlist-stale", "{}/{}".format(entry.kind, entry.record), "the gap is gone or was never reported; delete the entry ({})".format(entry.ticket))
        for entry in KNOWN_GAPS
        if (entry.kind, entry.record) not in reported
    ]
    return Report(rows=tuple(rows), gaps=tuple(unexpected), allowed=tuple(sorted(allowed, key=lambda gap: gap.as_key())), stale=tuple(stale))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def format_matrix(rows: Sequence[Row]) -> str:
    """Render the coverage matrix as aligned text, one block per record kind."""
    lines: list[str] = []
    titles = {
        "route": "HTTP routes (POST /rest_api/<name>)",
        "action": "action catalog identifiers (values, not paths)",
        "wss": "WSS registry records",
    }
    for kind in ("route", "action", "wss"):
        block = [row for row in rows if row.kind == kind]
        lines.append("")
        lines.append("== {} : {} ==".format(titles[kind], len(block)))
        if not block:
            lines.append("  (none)")
            continue
        columns = (
            ("record", [row.record for row in block]),
            ("implemented", [row.implemented for row in block]),
            ("documented", [row.documented for row in block]),
            ("openapi", [row.openapi for row in block]),
            ("simulator", [row.simulator for row in block]),
        )
        widths = [max(len(title), *(len(value) for value in values)) for title, values in columns]
        template = "  " + "  ".join("{:<%d}" % width for width in widths)
        lines.append(template.format(*(title for title, _ in columns)))
        lines.append("  " + "-" * (sum(widths) + 2 * (len(widths) - 1)))
        for row in block:
            lines.append(
                template.format(
                    row.record, row.implemented, row.documented, row.openapi, row.simulator
                )
            )
    return "\n".join(lines)


def format_report(report: Report, root: Path = ROOT) -> str:
    """Render the full report: summary, gaps, allow-list."""
    counts = {
        kind: sum(1 for row in report.rows if row.kind == kind)
        for kind in ("route", "action", "wss")
    }
    lines = [
        "API coverage: {} routes, {} action identifiers, {} WSS records ({} records total)".format(
            counts["route"], counts["action"], counts["wss"], len(report.rows)
        ),
        "Repository root: {}".format(root),
    ]
    if report.gaps:
        lines.append("")
        lines.append("Gaps ({}):".format(len(report.gaps)))
        for gap in report.gaps:
            lines.append("  {:<34} {:<28} {}".format(gap.kind, gap.record, gap.detail))
    if report.allowed:
        lines.append("")
        lines.append("Known gaps on the allow-list ({}), each one a bug ticket:".format(len(report.allowed)))
        for gap in report.allowed:
            lines.append("  {:<34} {:<28} {}".format(gap.kind, gap.record, gap.detail))
    if report.stale:
        lines.append("")
        lines.append("Stale allow-list entries ({}):".format(len(report.stale)))
        for gap in report.stale:
            lines.append("  {:<34} {}".format(gap.kind, gap.detail))
    lines.append("")
    lines.append("Result: {}".format("PASS" if report.ok else "FAIL"))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the checker from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(ROOT), help="repository root to check (default: this checkout)")
    parser.add_argument("--quiet", action="store_true", help="print gaps only, never the matrix")
    parser.add_argument("--json", action="store_true", help="print a machine-readable report instead of text")
    arguments = parser.parse_args(argv)
    root = Path(arguments.root).resolve()
    try:
        report = evaluate(root)
    except CheckError as error:
        print("api_coverage: {}".format(error), file=sys.stderr)
        return EXIT_INPUT_ERROR
    if arguments.json:
        payload = {
            "root": str(root),
            "ok": report.ok,
            "counts": {kind: sum(1 for row in report.rows if row.kind == kind) for kind in ("route", "action", "wss")},
            "rows": [row.__dict__ for row in report.rows],
            "gaps": [gap.__dict__ for gap in report.gaps],
            "allowed": [gap.__dict__ for gap in report.allowed],
            "stale": [gap.__dict__ for gap in report.stale],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if report.ok else 1
    if not arguments.quiet:
        print(format_matrix(report.rows))
    print(format_report(report, root))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
