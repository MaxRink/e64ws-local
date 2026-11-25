#!/usr/bin/env python3
"""Generate a C++ stub backend for the vendor QML from the parsed moc metadata.

Every moc class becomes a QObject with the same Q_PROPERTY / signal / Q_INVOKABLE
surface, all values default-initialised.  Child object properties are created on
first access so that deep property chains in the QML never hit a null pointer.
"""
from __future__ import annotations

import json
import pathlib
import re

MOC = json.load(open("/tmp/qml-recon/work/moc.json"))
PTR_TYPES = set()
for _v in MOC.values():
    for _p in _v["properties"]:
        if _p["type"].endswith("*"):
            PTR_TYPES.add(_p["type"][:-1].strip())
    for _m in _v["methods"]:
        for _t in [_m["ret"]] + _m["args"]:
            if _t.endswith("*"):
                PTR_TYPES.add(_t[:-1].strip())
PTR_SHORT = {t.split("::")[-1] for t in PTR_TYPES}
KEY_SHORT = {}
for _k in MOC:
    KEY_SHORT.setdefault(_k.split("::")[-1], _k)

QT_TYPES = {
    "bool", "int", "uint", "double", "float", "qlonglong", "qulonglong",
    "uint16_t", "QString", "QStringList", "QDateTime", "QDate", "QTime",
    "QUrl", "QColor", "QByteArray", "QVariant", "QVariantMap", "QVariantList",
    "QVariantHash", "QJsonArray", "QJsonObject", "QJsonValue", "QSize",
    "QSizeF", "QRectF", "QPointF", "QPoint", "QRect", "QTextFormat",
    "QPersistentModelIndex", "QChar", "QVariantHash",
}
GUI_VALTYPES = {"QColor", "QFont", "QImage", "QPixmap", "QPen", "QBrush",
                "QIcon", "QPalette", "QPolygon", "QPolygonF", "QRegion",
                "QBitmap", "QCursor", "QKeySequence", "QTextLength",
                "QTransform", "QMatrix4x4", "QVector2D", "QVector3D",
                "QVector4D", "QQuaternion", "QColorSpace"}
QT_OBJECT_TYPES = {"QObject*", "QQmlComponent*", "QStringListModel*",
                   "QSslSocket*", "QAbstractItemModel*"}

QOBJECT_API = {
    "objectName", "parent", "children", "deleteLater", "destroyed", "event",
    "eventFilter", "installEventFilter", "removeEventFilter", "findChild",
    "findChildren", "dumpObjectTree", "dumpObjectInfo", "inherits",
    "setObjectName", "setParent", "blockSignals", "signalsBlocked",
    "connect", "disconnect", "metaObject", "property", "setProperty",
    "sender", "thread", "timerEvent", "childEvent", "customEvent",
    "connectNotify", "disconnectNotify", "startTimer", "killTimer",
    "metaObject", "qt_metacast", "qt_metacall", "tr", "trUtf8",
}

PRIM_DEFAULT = {
    "bool": "false", "int": "0", "uint": "0", "double": "0", "float": "0",
    "qlonglong": "0", "qulonglong": "0", "uint16_t": "0",
    "QString": "QString()", "QStringList": "QStringList()",
    "QDateTime": "QDateTime()", "QDate": "QDate()", "QTime": "QTime()",
    "QUrl": "QUrl()", "QColor": "QColor()", "QByteArray": "QByteArray()",
    "QVariantMap": "QVariantMap()", "QVariantList": "QVariantList()",
    "QVariantHash": "QVariantHash()", "QJsonArray": "QJsonArray()",
    "QJsonObject": "QJsonObject()", "QJsonValue": "QJsonValue()",
    "QSize": "QSize()", "QSizeF": "QSizeF()", "QRectF": "QRectF()",
    "QRect": "QRect()", "QPointF": "QPointF()", "QPoint": "QPoint()",
    "QTextFormat": "QTextFormat()", "QPersistentModelIndex": "QPersistentModelIndex()",
    "QChar": "QChar()",
}


# classes that are visual items in the vendor build (QQuickItem subclasses)
BASE_OVERRIDE = {"QRCodeItem": "QQuickItem"}


def san(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


KEY2FULL = {"__".join(k.split("::")): k for k in MOC}


def merged(full):
    """properties/signals/methods of a class including in-binary ancestors"""
    chain = []
    cur = full
    while cur and cur in MOC and len(chain) < 8:
        chain.append(cur)
        sup = MOC[cur].get("super")
        cur = KEY2FULL.get(sup) if sup and sup != "QObject" else None
    chain.reverse()
    props, sigs, meths = {}, {}, {}
    for name in chain:
        c = MOC[name]
        for p in c["properties"]:
            props[p["name"]] = p
        for sg in c["signals"]:
            sigs[sg["name"]] = sg
        for m in c["methods"]:
            meths.setdefault(m["name"], m)
    return list(props.values()), list(sigs.values()), list(meths.values())


by_full = {}
by_short = {}
for full in MOC:
    cls = "Stub_" + san(full)
    by_full[full] = cls
    by_short.setdefault(full.split("::")[-1], cls)


TYPE_OVERRIDE = {
    # QML calls members of the concrete class through a base-typed property
    "AgsaDriver::AbstractAgsaController*": "AgsaDriver::AgsaController*",
    "GrindDriver::AbstractGrindController*": "GrindDriver::GrindController*",
}


def ctype(t: str, *, out_of_line: bool = True) -> str:
    t = t.strip()
    if t in TYPE_OVERRIDE:
        t = TYPE_OVERRIDE[t]
    for suffix in (" const", "&"):
        if t.endswith(suffix):
            t = t[: -len(suffix)]
    if t in GUI_VALTYPES:
        return "QVariant"
    if t in QT_TYPES:
        return t
    if t in QT_OBJECT_TYPES:
        return t
    if t.endswith("*"):
        base = t[:-1].strip()
        base = base.replace("const ", "").strip()
        if base in by_full:
            return by_full[base] + "*"
        short = base.split("::")[-1]
        if short in by_short:
            return by_short[short] + "*"
        return "QObject*"
    if t.startswith(("QVector<", "QList<", "std::optional<", "QQmlListProperty<",
                     "QList<QVariantMap>", "QVector<int>")):
        return "QVariant"
    if t in ("QList<QSslError>", "QVector<QString>", "QVector<Alert>",
             "QVector<Recipe>", "QList<TimeZoneCategory>", "QList<int>",
             "QList<NgxSqliteTypes::ReminderInterval>"):
        return "QVariant"
    # value classes with properties are exposed as stub objects so that QML can
    # read their members
    if t in by_short and MOC.get(KEY_SHORT.get(t, ""), {}).get("properties"):
        return by_short[t] + "*"
    if t in by_full and MOC[t].get("properties"):
        return by_full[t] + "*"
    # enum or plain value -> int keeps arithmetic/comparisons working in QML
    if "::" in t or t in by_short or t in by_full:
        return "int"
    if t[:1].isupper():
        return "int"
    return "QVariant"


def default_value(t: str) -> str:
    if t in PRIM_DEFAULT:
        return PRIM_DEFAULT[t]
    if t.endswith("*"):
        return "nullptr"
    if t == "QVariant":
        return "QVariant()"
    return "0"


lines = []
late = []
late_methods = []
namespaces = []
lines.append("// generated by gen_stub.py from moc metadata of libNgxUi.so")
lines.append("#pragma once")
lines.append("#include <QtCore>")
lines.append("#include <QtQml>")
lines.append("#include <QtGui>")
lines.append("#include <QtQuick>")
lines.append("")
lines.append("namespace NgxStub {")
lines.append("")
for full in sorted(MOC):
    lines.append(f"class {by_full[full]};")
lines.append("")
lines.append("class StubObject : public QObject { Q_OBJECT public: "
             "explicit StubObject(QObject *p=nullptr):QObject(p){} };")
lines.append("")

registration = []

for full, c in sorted(MOC.items()):
    cls = by_full[full]
    short = full.split("::")[-1]
    mprops, msigs, mmeths = merged(full)
    props = [p for p in mprops if p["name"] not in QOBJECT_API]
    # de-duplicate property names
    seen = set()
    uniq = []
    for p in props:
        if p["name"] in seen:
            continue
        seen.add(p["name"])
        uniq.append(p)
    props = uniq
    signals = []
    sig_seen = set()
    for s in msigs:
        if s["name"] in QOBJECT_API or s["name"] in sig_seen:
            continue
        sig_seen.add(s["name"])
        signals.append(s)
    methods = []
    m_seen = set()
    for m in mmeths:
        nm = m["name"]
        if m["kind"] == "signal" or nm in QOBJECT_API or nm in m_seen or nm.startswith("qt_"):
            continue
        if nm.startswith("set") and nm[3:].lower() in {p["name"].lower() for p in props}:
            continue
        m_seen.add(nm)
        methods.append(m)

    is_ns = ((not props) and (not methods) and bool(c["enums"])
             and full not in PTR_TYPES and short not in PTR_SHORT)
    base = BASE_OVERRIDE.get(short, "QObject")
    if is_ns:
        lines.append(f"namespace {cls}_ns {{")
        lines.append("    Q_NAMESPACE")
        used = set()
        for e in c["enums"]:
            vals = []
            for vn, vv in e["values"]:
                if vn in used or vn in ("",) or not vn[0].isalpha():
                    continue
                used.add(vn)
                vals.append(f"{vn} = {vv}")
            if not vals:
                continue
            lines.append(f"    enum {e['name']} {{ {', '.join(vals)} }};")
            lines.append(f"    Q_ENUM_NS({e['name']})")
        lines.append("}")
        lines.append("")
        namespaces.append((cls, short))
        continue
    lines.append(f"class {cls} : public {base} {{")
    lines.append("    Q_OBJECT")
    lines.append('    Q_CLASSINFO("DefaultProperty", "stubChildren")')
    lines.append("public:")
    ctor_arg = "QQuickItem *p = nullptr" if base == "QQuickItem" else "QObject *p = nullptr"
    lines.append(f"    explicit {cls}({ctor_arg}) : {base}(p) {{}}")
    lines.append("    Q_PROPERTY(QQmlListProperty<QObject> stubChildren READ stubChildren)")
    lines.append("    QQmlListProperty<QObject> stubChildren()"
                 " { return QQmlListProperty<QObject>(this, &m_stubChildren); }")
    lines.append("    QList<QObject *> m_stubChildren;")
    for p in props:
        ct = ctype(p["type"])
        nm = p["name"]
        lines.append(f"    Q_PROPERTY({ct} {nm} READ get_{nm} WRITE set_{nm} "
                     f"NOTIFY sig_{nm})")
    lines.append("")
    for p in props:
        ct = ctype(p["type"])
        nm = p["name"]
        if ct.endswith("*"):
            base = ct[:-1]
            lines.append(f"    {ct} get_{nm}();")
            lines.append(f"    void set_{nm}({ct} v);")
            lines.append(f"    {ct} m_{nm} = nullptr;")
            late.append((cls, ct, base, nm))
        else:
            dv = default_value(ct)
            lines.append(f"    {ct} get_{nm}() const {{ return m_{nm}; }}")
            lines.append(f"    void set_{nm}({ct} v) {{ m_{nm} = v; emit sig_{nm}(); }}")
            lines.append(f"    {ct} m_{nm} = {dv};")
    lines.append("")
    for m in methods:
        ret = ctype(m["ret"])
        args = []
        for i, a in enumerate(m["args"]):
            args.append(f"{ctype(a)} a{i}")
        name = m["name"]
        special = {
            ("QmlHelpers", "correctColor"):
                "return QVariant::fromValue(QColor(a0.toString()));",
            ("QmlHelpers", "colorAlpha"):
                "{ QColor c = a0.value<QColor>(); c.setAlphaF(a1);"
                " return QVariant::fromValue(c); }",
        }.get((full, name))
        if special:
            body = "{ " + special + " }"
        else:
            body = "{ " + ("return new " + ret[:-1] + "();" if ret.endswith("*") and ret != "QObject*" else
                       "return QVariant();" if ret == "QVariant" else
                       ("return nullptr;" if ret.endswith("*") else
                        f"return {default_value(ret)};")) + " }"
        if ret.endswith("*") and ret != "QObject*":
            lines.append(f"    Q_INVOKABLE {ret} {name}({', '.join(args)});")
            late_methods.append((cls, ret, ret[:-1], name, ", ".join(args)))
        else:
            lines.append(f"    Q_INVOKABLE {ret} {name}({', '.join(args)}) {body}")
    if methods:
        lines.append("")
    if c["enums"]:
        used = set()
        for e in c["enums"]:
            vals = []
            for vn, vv in e["values"]:
                if vn in used or vn in ("",) or not vn[0].isalpha():
                    continue
                used.add(vn)
                vals.append(f"{vn} = {vv}")
            if not vals:
                continue
            lines.append(f"    enum {e['name']} {{ {', '.join(vals)} }};")
            lines.append(f"    Q_ENUM({e['name']})")
        lines.append("")
    lines.append("signals:")
    for s in signals:
        args = [ctype(a) for a in s["args"]]
        lines.append(f"    void {s['name']}({', '.join(args)});")
    for p in props:
        lines.append(f"    void sig_{p['name']}();")
    lines.append("};")
    lines.append("")
    registration.append((cls, short, len(props), len(signals), len(methods)))

for cls, ct, base, nm, args in late_methods:
    lines.append(f"inline {ct} {cls}::{nm}({args}) {{ return new {base}(); }}")
for cls, ct, base, nm in late:
    lines.append(f"inline {ct} {cls}::get_{nm}() {{ if (!m_{nm}) m_{nm} = new {base}(this); return m_{nm}; }}")
    lines.append(f"inline void {cls}::set_{nm}({ct} v) {{ m_{nm} = v; emit sig_{nm}(); }}")
lines.append("")
# duplicate the NgxSqliteTypes enums under the QML name "Enums" (the vendor
# exposes the same enum set twice under different names)
def emit_ns(nsname, enums):
    out = [f"namespace {nsname} {{", "    Q_NAMESPACE"]
    used = set()
    for e in enums:
        vals = []
        for vn, vv in e["values"]:
            if vn in used or vn in ("",) or not vn[0].isalpha():
                continue
            used.add(vn)
            vals.append(f"{vn} = {vv}")
        if not vals:
            continue
        out.append(f"    enum {e['name']} {{ {', '.join(vals)} }};")
        out.append(f"    Q_ENUM_NS({e['name']})")
    out.append("}")
    out.append("")
    return out

if "NgxSqliteTypes" in MOC:
    lines.extend(emit_ns("NgxEnums_ns", MOC["NgxSqliteTypes"]["enums"]))

lines.append("inline void registerQml() {")
if "NgxSqliteTypes" in MOC:
    lines.append('    qmlRegisterUncreatableMetaObject(NgxEnums_ns::staticMetaObject, '
                 '"NgxApi", 1, 0, "Enums", "enum stub");')
for cls, short in namespaces:
    lines.append(f'    qmlRegisterUncreatableMetaObject({cls}_ns::staticMetaObject, '
                 f'"NgxApi", 1, 0, "{short}", "enum stub");')
for cls, short, np, ns, nm in registration:
    lines.append(f'    qmlRegisterType<{cls}>("NgxApi", 1, 0, "{short}");')
lines.append("}")
lines.append("")
lines.append("inline QObject *make(const QByteArray &name) {")
for cls, short, *_ in registration:
    lines.append(f'    if (name == "{short}") return new {cls}();')
lines.append("    return new StubObject();")
lines.append("}")
lines.append("} // namespace NgxStub")

out = pathlib.Path("/tmp/qml-recon/build/stubs.h")
out.write_text("\n".join(lines) + "\n")
print("wrote", out, len(lines), "lines,", len(registration), "classes")
print("total properties:", sum(r[2] for r in registration),
      "signals:", sum(r[3] for r in registration),
      "methods:", sum(r[4] for r in registration))
