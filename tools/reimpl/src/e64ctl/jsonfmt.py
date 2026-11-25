"""JSON serialisation compatible with Qt's ``QJsonDocument::toJson()``.

The vendor connector replies with ``QJsonDocument(out).toJson()`` (no argument),
i.e. Qt's *Indented* format: 4 spaces per level, ``": "`` between key and value,
one member per line, and a trailing newline after the final brace.  The
compact form is offered for tooling and for harnesses that compare parsed JSON.

Number formatting is Qt-like but not bit-identical: Qt 5.15 prints the shortest
round-trip representation of a double and drops the fractional part for
integral values (``18.0`` -> ``18``).  Python's ``repr`` is also shortest
round-trip, so ``18.0`` -> ``18`` is reproduced explicitly.  This is the one
known formatting approximation (see REPORT.md).
"""
from __future__ import annotations

import math
from typing import Any

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape(text: str) -> str:
    out = ['"']
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: float | int) -> str:
    if isinstance(value, bool):  # bool is an int subclass
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        return "null"  # Qt serialises non-finite doubles as null
    if value == int(value) and abs(value) < 1e16:
        return str(int(value))
    return repr(value)


def dumps(value: Any, indented: bool = True) -> str:
    if indented:
        return _dump(value, 0) + "\n"
    return _dump(value, None)


def _dump(value: Any, level: int | None) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, dict):
        if not value:
            return "{}"
        # QJsonObject keeps its members sorted by key (Qt5), so toJson() emits
        # them alphabetically. The vendor capture in
        # tools/virtual-grinder/docs/evidence/wss-driver-state.json confirms it.
        items = sorted(value.items(), key=lambda item: str(item[0]))
        if level is None:
            return "{" + ",".join(
                f"{_escape(str(k))}:{_dump(v, None)}" for k, v in items
            ) + "}"
        pad = "    " * (level + 1)
        body = ",\n".join(
            f"{pad}{_escape(str(k))}: {_dump(v, level + 1)}"
            for k, v in items
        )
        return "{\n" + body + "\n" + "    " * level + "}"
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        if level is None:
            return "[" + ",".join(_dump(v, None) for v in value) + "]"
        pad = "    " * (level + 1)
        body = ",\n".join(f"{pad}{_dump(v, level + 1)}" for v in value)
        return "[\n" + body + "\n" + "    " * level + "]"
    raise TypeError(f"cannot serialise {type(value)!r}")


def loads(data: str | bytes) -> Any:
    import json

    return json.loads(data)
