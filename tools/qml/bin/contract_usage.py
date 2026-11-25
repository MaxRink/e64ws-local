#!/usr/bin/env python3
"""Cross-reference the QML member accesses with the moc metadata of libNgxUi.so.

Produces:
  * per-root-object coverage (which properties/methods the QML touches exist)
  * a list of accesses that no C++ symbol provides (the "missing symbol" list)
  * a list of QML-declared C++ types
"""
from __future__ import annotations

import collections
import json
import pathlib
import re

MOC = json.load(open("/tmp/qml-recon/work/moc.json"))
ROOT = pathlib.Path("/tmp/qml-recon/qrc/Ui/Qml")
KEY2FULL = {"__".join(k.split("::")): k for k in MOC}
SHORT2FULL = {}
for k in MOC:
    SHORT2FULL.setdefault(k.split("::")[-1], k)

ROOTS = {
    "service": "Service",
    "uiState": "UiStateController",
    "demoProtoIface": "DemonstratorProtoIface",
    "machineConfig": "MachineConfig",
    "systemVariantManager": "SystemVariantManager",
    "espFlashHandler": "EspDriver::EspFlashHandler",
    "splashScreenHelper": "SplashScreenHelper",
}


def members(cls):
    """property/method names of a class incl. in-binary ancestors"""
    props, meths = {}, {}
    chain, cur = [], cls
    while cur and cur in MOC and len(chain) < 8:
        chain.append(cur)
        sup = MOC[cur].get("super")
        cur = KEY2FULL.get(sup) if sup and sup != "QObject" else None
    for name in reversed(chain):
        c = MOC[name]
        for p in c["properties"]:
            props[p["name"]] = p["type"]
        for m in c["methods"]:
            meths.setdefault(m["name"], m)
    return props, meths


def resolve(t):
    t = t.strip().rstrip("*").replace("const ", "").strip()
    if t in MOC:
        return t
    if t in SHORT2FULL:
        return SHORT2FULL[t]
    return None


PATHS = re.compile(r'\b(' + "|".join(ROOTS) + r')((?:\.[A-Za-z_]\w*)+)')
declared_types = collections.Counter()
declared_files = collections.defaultdict(set)
used = collections.defaultdict(collections.Counter)   # "root.member" -> count
accesses = collections.Counter()

for f in ROOT.rglob("*.qml"):
    text = f.read_text(errors="replace")
    for m in re.finditer(r'^\s*(?:required\s+)?(?:readonly\s+)?property\s+([A-Za-z_][\w.]*)\s+\w+',
                         text, re.M):
        declared_types[m.group(1)] += 1
        declared_files[m.group(1)].add(str(f.relative_to(ROOT)))
    text = re.sub(r'//[^\n]*', '', text)
    for m in PATHS.finditer(text):
        parts = m.group(2).strip(".").split(".")
        accesses[m.group(1) + "." + parts[0]] += 1
        # first level must exist on the root
        props, meths = members(ROOTS[m.group(1)])
        if parts[0] not in props and parts[0] not in meths:
            used[m.group(1) + "." + parts[0]]["MISSING"] += 1
            continue
        t = resolve(props.get(parts[0], ""))
        used[m.group(1) + "." + parts[0]][parts[0]] += 1
        # walk deeper when the type is known
        for part in parts[1:]:
            if not t:
                break
            p2, m2 = members(t)
            if part in p2:
                used[f"{t}.{part}"][part] += 1
                t = resolve(p2[part])
            elif part in m2:
                used[f"{t}.{part}"][part] += 1
                t = None
            else:
                used[f"{t}.{part}"]["MISSING"] += 1
                break

total = sum(accesses.values())
missing = [(k, v["MISSING"]) for k, v in used.items() if "MISSING" in v]
print(f"QML files: {len(list(ROOT.rglob('*.qml')))}, js: {len(list(ROOT.rglob('*.js')))}")
print(f"context access sites: {total} over {len(accesses)} distinct root.member pairs")
print(f"distinct types in QML property declarations: {len(declared_types)}")
cpp_types = sorted(t for t in declared_types if t.split("::")[-1] in SHORT2FULL)
print(f"  of those provided by libNgxUi moc: {len(cpp_types)}")
print("\n== missing members on context objects")
for k, v in sorted(missing):
    print(f"  {k:60} {v}")
print("\n== context roots: distinct members used")
for r in ROOTS:
    n = len([k for k in accesses if k.startswith(r + ".")])
    print(f"  {r:22} {n}")
print("\n== deepest chains checked")
deep = [k for k in used if k.count(".") >= 2]
print(f"  {len(deep)} member paths resolved through a property type")

json.dump({"missing": missing,
           "accesses": dict(accesses),
           "declared_types": dict(declared_types)},
          open("/tmp/qml-recon/work/contract_usage.json", "w"), indent=1)
