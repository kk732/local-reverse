#!/usr/bin/env python3
"""列出 APK 里所有 dex 的类名（纯标准库，不依赖 jadx）。

用法：dex_classes.py <apk> [--grep 关键词] [--limit N] [--pkg]
输出单行 JSON：{"ok":true,"total":N,"classes":[...]}
"""
import json
import sys
import zipfile


def uleb128(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def read_string(buf, off):
    _len, off = uleb128(buf, off)
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return bytes(buf[off:end]).decode("utf-8", "replace")


def class_names_from_dex(buf):
    string_ids_size = int.from_bytes(buf[0x38:0x3C], "little")
    string_ids_off = int.from_bytes(buf[0x3C:0x40], "little")
    type_ids_size = int.from_bytes(buf[0x40:0x44], "little")
    type_ids_off = int.from_bytes(buf[0x44:0x48], "little")
    class_defs_size = int.from_bytes(buf[0x60:0x64], "little")
    class_defs_off = int.from_bytes(buf[0x64:0x68], "little")

    if not (0 < string_ids_size < 5_000_000 and string_ids_off + 4 * string_ids_size <= len(buf)):
        return []
    if not (0 < type_ids_off + 4 * type_ids_size <= len(buf)):
        return []
    if not (0 <= class_defs_off + 32 * class_defs_size <= len(buf)):
        return []

    strs = [read_string(buf, int.from_bytes(buf[string_ids_off + 4 * i: string_ids_off + 4 * i + 4], "little"))
            for i in range(string_ids_size)]

    out = []
    for i in range(class_defs_size):
        base = class_defs_off + 32 * i
        type_idx = int.from_bytes(buf[base:base + 4], "little")
        if type_idx >= type_ids_size:
            continue
        str_idx = int.from_bytes(buf[type_ids_off + 4 * type_idx: type_ids_off + 4 * type_idx + 4], "little")
        if str_idx >= len(strs):
            continue
        desc = strs[str_idx]
        if desc.startswith("L") and desc.endswith(";"):
            desc = desc[1:-1]
        out.append(desc.replace("/", "."))
    return out


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "缺少 APK 路径"}))
        return
    path = sys.argv[1]
    grep = None
    limit = 200
    pkg_only = False
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--grep" and i + 1 < len(args):
            grep = args[i + 1].lower()
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = max(1, int(args[i + 1]))
            i += 2
        elif args[i] == "--pkg":
            pkg_only = True
            i += 1
        else:
            i += 1

    names = []
    try:
        with zipfile.ZipFile(path) as z:
            dexes = sorted(n for n in z.namelist() if n.startswith("classes") and n.endswith(".dex"))
            for n in dexes:
                with z.open(n) as f:
                    names.extend(class_names_from_dex(f.read()))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}))
        return

    total = len(names)
    if grep:
        names = [c for c in names if grep in c.lower()]
    if pkg_only:
        pkgs = {}
        for c in names:
            p = c.rsplit(".", 1)[0] if "." in c else c
            pkgs[p] = pkgs.get(p, 0) + 1
        items = sorted(pkgs.items(), key=lambda kv: -kv[1])[:limit]
        print(json.dumps({"ok": True, "total": total, "matched": len(names),
                          "packages": [{"name": k, "count": v} for k, v in items]}, ensure_ascii=False))
        return

    print(json.dumps({"ok": True, "total": total, "matched": len(names), "classes": names[:limit]},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
