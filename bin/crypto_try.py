#!/usr/bin/env python3
"""试着用包里找到的候选 key 解密高熵资源（AES-ECB / AES-CBC 零 IV）。

这是猜谜，不是保证：只对固定 key 直接加密的载荷有效，加固壳把 key 放在 so 里
或做二次变换时解不开。

用法：crypto_try.py <apk> [--limit N]
输出单行 JSON：{"ok":true,"keys":N,"files":N,"attempts":N,"hits":[{file,key,mode,magic}]}
"""
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_scan import (  # noqa: E402
    HEXKEY,
    KEYLIKE,
    NOISY_EXT,
    SUSPECT_ASSET,
    dex_strings,
    entropy,
)

def printable_ratio(buf):
    if not buf:
        return 0.0
    ok = sum(1 for b in buf if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(buf)


def verify(dec):
    """认出明文类型；只认头几个字节容易误报，所以顺带看后续字节像不像文本。"""
    if dec.startswith(b"dex\n") and dec[4:8][:3].isdigit():
        return "dex"
    if dec.startswith(b"PK\x03\x04") and printable_ratio(dec[30:94]) >= 0.6:
        return "zip"
    if dec.startswith(b"\x1f\x8b"):
        return "gzip"
    if dec.startswith(b"SQLite format 3"):
        return "sqlite"
    if dec.startswith(b"<?xml") and printable_ratio(dec[:64]) >= 0.9:
        return "xml"
    if dec[:1] in (b"{", b"[") and printable_ratio(dec[:96]) >= 0.92:
        return "json"
    return None


def find_keys(strs):
    keys = []
    for s in strs:
        if not (KEYLIKE.match(s) or HEXKEY.match(s)) or sum(c.isdigit() for c in s) < 2:
            continue
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", s) and s[0].isupper() and any(c.islower() for c in s):
            continue
        if re.search(r"[a-z]{5,}", s) and not re.search(r"[A-Z]{3,}", s):
            continue
        if re.fullmatch(r"[A-Z0-9]+(?:_[A-Z0-9]+)+", s):
            continue  # 全大写常量名
        if "_" in s and re.search(r"[a-z]", s):
            continue  # 带下划线的驼峰名
        if "-" in s:
            continue  # kebab 名（前端打包产物）
        if re.fullmatch(r"[a-z][A-Za-z0-9]*", s) and any(c.isupper() for c in s):
            continue  # 小驼峰标识符
        b = s.encode("utf-8", "replace")
        if len(b) not in (16, 24, 32) and not HEXKEY.match(s):
            continue
        raw = bytes.fromhex(s) if HEXKEY.match(s) and len(s) % 2 == 0 else b
        if len(raw) in (16, 24, 32):
            keys.append((s, raw))
    return keys[:24]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "缺少 APK 路径"}))
        return
    path = sys.argv[1]
    limit = 12
    if "--limit" in sys.argv:
        try:
            limit = max(1, int(sys.argv[sys.argv.index("--limit") + 1]))
        except (IndexError, ValueError):
            pass

    try:
        from Crypto.Cipher import AES
    except Exception:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": "没装 pycryptodome"}))
        return

    strs = []
    targets = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in sorted(x for x in z.namelist() if x.startswith("classes") and x.endswith(".dex")):
                with z.open(n) as f:
                    strs.extend(dex_strings(f.read()))
            for info in z.infolist():
                name = info.filename
                if name.endswith("/") or info.file_size < 512 or info.file_size > 24 * 1024 * 1024:
                    continue
                if not (name.startswith("assets/") or name.startswith("res/raw/")):
                    continue
                if name.lower().endswith(NOISY_EXT):
                    continue
                if not (SUSPECT_ASSET.search(name) or info.file_size >= 4096):
                    continue
                targets.append((name, info.file_size))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}))
        return

    keys = find_keys(strs)
    targets = targets[:limit]
    hits = []
    attempts = 0
    if keys and targets:
        with zipfile.ZipFile(path) as z:
            for name, _size in targets:
                with z.open(name) as f:
                    blob = f.read(4096)
                blob = blob[: len(blob) - len(blob) % 16]
                if not blob:
                    continue
                for shown, raw in keys:
                    for mode, kwargs in (("ECB", {}), ("CBC-0IV", {"iv": b"\x00" * 16})):
                        attempts += 1
                        try:
                            if mode == "ECB":
                                dec = AES.new(raw, AES.MODE_ECB).decrypt(blob)
                            else:
                                dec = AES.new(raw, AES.MODE_CBC, kwargs["iv"]).decrypt(blob)
                        except Exception:  # noqa: BLE001
                            continue
                        magic = verify(dec)
                        if magic:
                            hits.append({"file": name, "key": shown, "mode": mode, "magic": magic})
                            break
    print(json.dumps({
        "ok": True,
        "keys": len(keys),
        "files": len(targets),
        "attempts": attempts,
        "hits": hits[:8],
        "targets": [t[0] for t in targets[:6]],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
