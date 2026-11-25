#!/usr/bin/env python3
"""Parse Qt moc metadata out of libNgxUi.so and dump the QObject API of every class.

Layout used (Qt 5.15, ELF32, revision 8):
  staticMetaObject: superdata(+0) stringdata(+4) data(+8) static_metacall(+12)
  QMetaObjectPrivate: rev, className, classInfoCount/Data, methodCount/Data,
      propertyCount/Data, enumeratorCount/Data, constructorCount/Data,
      flags, signalCount
  all *Data fields are uint indices into the data array.
  method entry (5 uints): name, argc, parameters, tag, flags
  parameter list: argc+1 uints (return type first); 0x80000000|idx -> stringdata
  property entry (3 uints): name, type, flags
  enum entry (5 uints): name, alias, flags, count, data; values (2 uints each)
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from elfview import Elf  # noqa: E402

QT_CORE = {
    0x0: "void", 0x1: "bool", 0x2: "int", 0x3: "uint", 0x4: "qlonglong",
    0x5: "qulonglong", 0x6: "double", 0x7: "QChar", 0x8: "QVariantMap",
    0x9: "QVariantList", 0xA: "QString", 0xB: "QStringList", 0xC: "QByteArray",
    0xD: "QBitArray", 0xE: "QDate", 0xF: "QTime", 0x10: "QDateTime",
    0x11: "QUrl", 0x12: "QLocale", 0x13: "QRect", 0x14: "QRectF", 0x15: "QSize",
    0x16: "QSizeF", 0x17: "QLine", 0x18: "QLineF", 0x19: "QPoint", 0x1A: "QPointF",
    0x1B: "QRegExp", 0x1C: "QEasingCurve", 0x1D: "QUuid", 0x1E: "QVariant",
    0x1F: "QModelIndex", 0x20: "QPersistentModelIndex", 0x21: "QRegularExpression",
    0x22: "QJsonValue", 0x23: "QJsonObject", 0x24: "QJsonArray",
    0x25: "QJsonDocument", 0x26: "QByteArrayList", 0x27: "QPersistentModelIndex",
    0x28: "QObject*", 0x2B: "QStringList", 0x2C: "QTextFormat",
    0x2D: "QTextLayout", 0x2E: "QVariantHash", 0x30: "QCborValue",
    0x31: "QCborArray", 0x32: "QCborMap", 0x33: "QCborSimpleType",
    0x34: "QVector2D", 0x35: "QVector3D", 0x36: "QVector4D", 0x37: "QQuaternion",
    # GUI types (QMetaType 64..87)
    64: "QFont",
    65: "QPixmap",
    66: "QBrush",
    67: "QColor",
    68: "QPalette",
    69: "QIcon",
    70: "QImage",
    71: "QPolygon",
    72: "QRegion",
    73: "QBitmap",
    74: "QCursor",
    75: "QKeySequence",
    76: "QPen",
    77: "QTextLength",
    78: "QTextFormat",
    79: "QMatrix",
    80: "QTransform",
    81: "QMatrix4x4",
    82: "QVector2D",
    83: "QVector3D",
    84: "QVector4D",
    85: "QQuaternion",
    86: "QPolygonF",
    87: "QColorSpace",
}


def itanium_local_key(sym: str) -> str:
    """_ZN10AgsaDriver18AgsaDdSensorConfig16staticMetaObjectE -> AgsaDriver__AgsaDdSensorConfig"""
    s = sym
    if s.startswith("_ZN"):
        s = s[3:]
    elif s.startswith("_ZL"):
        s = s[3:]
    parts = []
    i = 0
    while i < len(s) and s[i].isdigit():
        j = i
        while j < len(s) and s[j].isdigit():
            j += 1
        n = int(s[i:j])
        part = s[j:j + n]
        if part in ("staticMetaObject",):
            break
        parts.append(part)
        i = j + n
    return "__".join(parts)


def reloc_symbol_map(elf):
    """R_ARM_ABS32 relocations: file offset -> target symbol name."""
    rel = elf.section(".rel.dyn")
    if not rel:
        return {}
    dynsym = elf.section(".dynsym")
    dynstr = elf.sections[dynsym["link"]]
    out = {}
    entsize = rel["entsize"] or 8
    for i in range(rel["size"] // entsize):
        off = rel["offset"] + i * entsize
        r_offset, r_info = struct.unpack_from("<II", elf.blob, off)
        symidx = r_info >> 8
        if not symidx:
            continue
        so = dynsym["offset"] + symidx * dynsym["entsize"]
        nameoff, value = struct.unpack_from("<II", elf.blob, so)
        name = elf.cstr(dynstr["offset"] + nameoff)
        out[r_offset] = name
    return out


class Moc:
    def __init__(self, path: str):
        self.elf = Elf(path)
        self.classes = {}

    def load_strings(self, base: int):
        out = []
        for i in range(4000):
            a = base + i * 16
            try:
                ref, size, alloc, off = struct.unpack(
                    "<iiIi", self.elf.read_va(a, 16))
            except KeyError:
                break
            if not (0 <= size <= 1024) or not (-10_000_000 < off < 10_000_000):
                break
            try:
                s = self.elf.read_va(a + off, size)
            except KeyError:
                break
            try:
                txt = s.decode("utf-8")
            except UnicodeDecodeError:
                break
            if any(ord(c) < 0x20 for c in txt):
                break
            out.append(txt)
        return out

    def u(self, data_va, index, n=1):
        raw = self.elf.read_va(data_va + 4 * index, 4 * n)
        return struct.unpack("<" + "i" * n, raw)

    def type_name(self, t, strings):
        if t & 0x80000000:
            idx = t & 0x7FFFFFFF
            return strings[idx] if idx < len(strings) else f"?{idx}"
        return QT_CORE.get(t, f"type{t}")

    def parse(self):
        metas = [s for s in self.elf.symbols
                 if s["name"].endswith("staticMetaObjectE")]
        strsyms = {}
        for s in self.elf.symbols:
            if "qt_meta_stringdata_" in s["name"]:
                k = itanium_local_key(s["name"]).replace("qt_meta_stringdata_", "")
                strsyms[k] = s
        va_map = {s["value"]: s["name"] for s in metas}
        relocs = reloc_symbol_map(self.elf)
        for sym in metas:
            mo = sym["value"]
            try:
                superdata, stringdata, data, _ = struct.unpack(
                    "<IIII", self.elf.read_va(mo, 16))
            except KeyError:
                continue
            if not data:
                continue
            key = itanium_local_key(sym["name"])
            sd_sym = strsyms.get(key)
            if not sd_sym:
                continue
            try:
                hdr = self.u(data, 0, 14)
            except KeyError:
                continue
            rev = hdr[0]
            if rev not in (7, 8):
                continue
            strings = self.load_strings(sd_sym["value"])
            if not strings or not (0 <= hdr[1] < len(strings)):
                continue
            cls = strings[hdr[1]]
            (_, _, ci_c, ci_d, m_c, m_d, p_c, p_d, e_c, e_d, ctor_c,
             ctor_d, flags, sigc) = hdr
            info = dict(name=cls, revision=rev, properties=[], methods=[],
                        signals=[], enums=[], flags=flags, classinfo={},
                        super=None)
            for k in range(m_c):
                try:
                    name, argc, params, tag, mflags = self.u(data, m_d + 5 * k, 5)
                except KeyError:
                    break
                if not (0 <= name < len(strings)) or argc > 32:
                    continue
                try:
                    ptypes = self.u(data, params, argc + 1)
                except KeyError:
                    continue
                sig = [self.type_name(t, strings) for t in ptypes]
                kind = "signal" if (mflags & 0x07) == 0x06 else (
                    "slot" if (mflags & 0x08) else "method")
                rec = dict(name=strings[name], ret=sig[0], args=sig[1:],
                           kind=kind, flags=mflags)
                info["methods"].append(rec)
                if kind == "signal":
                    info["signals"].append(rec)
            for k in range(p_c):
                try:
                    name, typ, pfl = self.u(data, p_d + 3 * k, 3)
                except KeyError:
                    break
                if not (0 <= name < len(strings)):
                    continue
                info["properties"].append(dict(
                    name=strings[name], type=self.type_name(typ, strings),
                    flags=pfl, writable=bool(pfl & 2), constant=bool(pfl & 0x0400)))
            for k in range(e_c):
                try:
                    name, alias, efl, cnt, edata = self.u(data, e_d + 5 * k, 5)
                except KeyError:
                    break
                vals = []
                for j in range(min(cnt, 64)):
                    try:
                        vn, vv = self.u(data, edata + 2 * j, 2)
                    except KeyError:
                        break
                    if 0 <= vn < len(strings):
                        vals.append([strings[vn], vv])
                if 0 <= name < len(strings):
                    info["enums"].append(dict(name=strings[name], values=vals))
            supname = relocs.get(mo)
            if supname and "staticMetaObject" in supname:
                info["super"] = itanium_local_key(supname)
            elif superdata and superdata in va_map:
                info["super"] = va_map[superdata]
            for k in range(ci_c):
                kn, kv = self.u(data, ci_d + 2 * k, 2)
                if 0 <= kn < len(strings) and 0 <= kv < len(strings):
                    info["classinfo"][strings[kn]] = strings[kv]
            self.classes[cls] = info
        return self.classes


def main():
    m = Moc(sys.argv[1])
    classes = m.parse()
    print(f"parsed {len(classes)} moc classes")
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/qml-recon/work/moc.json"
    json.dump(classes, open(out, "w"), indent=1)
    for name in ("Service", "UiStateController", "DemonstratorProtoIface",
                 "SystemVariantManager", "ConfigManager", "MachineConfig"):
        c = classes.get(name)
        if not c:
            print("missing", name)
            continue
        print(f"\n== {name}: {len(c['properties'])} props, "
              f"{len(c['signals'])} signals, {len(c['methods'])} methods")
        for p in c["properties"]:
            print(f"   property {p['type']:<34} {p['name']}")
        for s in c["signals"][:6]:
            print(f"   signal   {s['name']}({', '.join(s['args'])})")


if __name__ == "__main__":
    main()
