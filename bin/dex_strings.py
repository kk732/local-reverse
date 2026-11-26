#!/usr/bin/env python3
"""扫 APK 里的 dex 字符串池，挑出 URL、IP、邮箱、疑似密钥这些逆向常看的线索。

用法：dex_strings.py <apk> [--limit N]
输出单行 JSON：{"ok":true,"total":N,"groups":[{"name":"URL","items":[...]}]}
"""
import json
import re
import sys
import zipfile

PATS = [
    ("URL", re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")),
    ("邮箱", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("疑似密钥", re.compile(r"(?:AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})")),
    ("密钥字段", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[=:]\s*[\"']?([A-Za-z0-9_\-./+=]{8,80})")),
]


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


def strings_from_dex(buf):
    size = int.from_bytes(buf[0x38:0x3C], "little")
    off = int.from_bytes(buf[0x3C:0x40], "little")
    if not (0 < size < 5_000_000 and off + 4 * size <= len(buf)):
        return []
    out = []
    for i in range(size):
        data_off = int.from_bytes(buf[off + 4 * i: off + 4 * i + 4], "little")
        if data_off >= len(buf):
            continue
        try:
            _n, pos = uleb128(buf, data_off)
        except IndexError:
            continue
        end = buf.find(b"\x00", pos)
        if end < 0 or end - pos < 4:
            continue
        out.append(bytes(buf[pos:end]).decode("utf-8", "replace"))
    return out


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "缺少 APK 路径"}))
        return
    path = sys.argv[1]
    limit = 40
    if "--limit" in sys.argv:
        try:
            limit = max(1, int(sys.argv[sys.argv.index("--limit") + 1]))
        except (IndexError, ValueError):
            pass

    allstr = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in sorted(x for x in z.namelist() if x.startswith("classes") and x.endswith(".dex")):
                with z.open(n) as f:
                    allstr.extend(strings_from_dex(f.read()))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}))
        return

    groups = []
    for name, pat in PATS:
        seen = []
        hit = set()
        for s in allstr:
            for m in pat.finditer(s):
                v = m.group(1) if m.groups() else m.group(0)
                if v in hit:
                    continue
                hit.add(v)
                seen.append(v)
        if seen:
            groups.append({"name": name, "total": len(seen), "items": seen[:limit]})

    # 顺便看看有没有明显的内网/调试地址
    debug_hosts = sorted({m for s in allstr for m in re.findall(r"\b(?:(?:10|127)(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2})(?::\d+)?\b", s)})
    if debug_hosts:
        groups.append({"name": "内网地址", "total": len(debug_hosts), "items": debug_hosts[:limit]})

    print(json.dumps({"ok": True, "total": len(allstr), "groups": groups}, ensure_ascii=False))


if __name__ == "__main__":
    main()
