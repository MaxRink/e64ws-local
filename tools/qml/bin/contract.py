#!/usr/bin/env python3
"""Extract the QML -> C++ backend contract from the vendor QML tree."""
from __future__ import annotations

import collections
import json
import pathlib
import re

ROOT = pathlib.Path("/tmp/qml-recon/qrc/Ui")
files = sorted(ROOT.rglob("*.qml")) + sorted(ROOT.rglob("*.js")) + sorted(ROOT.glob("**/qmldir"))

IMPORT = re.compile(r'^\s*import\s+(?!")([\w.]+)\s*([\d.]+)?', re.M)
PROP = re.compile(r'^\s*(?:readonly\s+)?property\s+([A-Za-z_][\w.<>]*)\s+([A-Za-z_]\w*)', re.M)
CTX = ("service", "uiState", "demoProtoIface", "machineConfig", "connectivity",
       "accessControl", "systemVariantManager", "espFlashHandler", "dbusClient",
       "logger", "config", "app")
MEMBER = re.compile(r'\b(' + "|".join(CTX) + r')\.([A-Za-z_]\w*)')

imports = collections.Counter()
declared = collections.Counter()          # C++-ish types used in property declarations
declared_files = collections.defaultdict(set)
members = collections.defaultdict(collections.Counter)   # ctx -> member counts
files_by_type = collections.defaultdict(set)
qmldir_singletons = {}

for f in files:
    text = f.read_text(errors="replace")
    for m in IMPORT.finditer(text):
        imports[m.group(1)] += 1
    for m in PROP.finditer(text):
        typ, name = m.group(1), m.group(2)
        if typ in ("var", "int", "real", "bool", "string", "url", "color", "list",
                   "alias", "double", "date", "point", "size", "rect", "vector2d",
                   "vector3d", "variant", "Item", "QtObject", "Component", "font"):
            continue
        declared[typ] += 1
        files_by_type[typ].add(str(f.relative_to(ROOT)))
    for m in MEMBER.finditer(text):
        members[m.group(1)][m.group(2)] += 1
    if f.name == "qmldir":
        for line in text.splitlines():
            p = line.split()
            if len(p) >= 3 and p[0] in ("singleton", "internal"):
                if p[0] == "singleton":
                    qmldir_singletons[p[1]] = f"{f.parent.name}/{p[-1]}"

# names used as types but not declared anywhere -> imported TypeNames
print("== imports")
for k, v in imports.most_common():
    print(f"  {v:>4}  {k}")
print("\n== property declarations with non-primitive types")
for k, v in declared.most_common():
    print(f"  {v:>4}  {k:<34} {', '.join(sorted(files_by_type[k])[:3])}")
print("\n== context object member accesses")
for ctx, c in members.items():
    print(f"  {ctx}: {len(c)} distinct members")
    print("     " + ", ".join(f"{k}({v})" for k, v in c.most_common()))
print("\n== qmldir singletons")
print("  " + ", ".join(sorted(qmldir_singletons)))

json.dump(dict(imports=imports, declared=declared,
               members={k: dict(v) for k, v in members.items()},
               singletons=qmldir_singletons),
          open("/tmp/qml-recon/work/contract.json", "w"), indent=1)
