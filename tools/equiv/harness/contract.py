"""Contract loading and rendering."""

from __future__ import annotations

import json
from pathlib import Path

CONFIDENCE_ORDER = {"observed": 0, "inferred": 1, "unknown": 2}


def load_contract(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def contract_table(contract: dict, surfaces: list[str] | None = None) -> str:
    rows = contract["entries"]
    if surfaces:
        rows = [r for r in rows if r["surface"] in surfaces]
    lines = []
    header = ("| ID | Surface | Dir | Input / record | Observable output | Conf |")
    lines.append(header)
    lines.append("|---|---|---|---|---|---|")
    for row in rows:
        name = row["name"]
        if row.get("action"):
            name = f"`GrinderAction/{row['action']}`" if row["surface"] == "wss" else name
        elif row["surface"] == "wss":
            name = f"`{name}`"
        shape = row.get("shape", "")
        if shape:
            name = f"{name}<br/>`{shape}`" if row["surface"] == "wss" else name
        output = row["observable"].replace("|", "\\|")
        lines.append(f"| {row['id']} | {row['surface']} | {row['direction']} | "
                     f"{name} | {output} | {row['confidence']} |")
    return "\n".join(lines)


def counts(contract: dict) -> dict:
    out: dict[str, dict[str, int]] = {}
    for row in contract["entries"]:
        surface = out.setdefault(row["surface"], {"observed": 0, "inferred": 0, "unknown": 0})
        surface[row["confidence"]] = surface.get(row["confidence"], 0) + 1
    return out
