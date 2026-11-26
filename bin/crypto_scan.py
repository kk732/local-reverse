#!/usr/bin/env python3
"""扫 APK 里的加密线索：算法调用、硬编码 key、高熵资源、可疑的加密 dex。

用法：crypto_scan.py <apk> [--limit N]
输出单行 JSON：{"ok":true,"algorithms":[{name,count}],"keys":[...],"entropy":[...],"notes":[...]}
"""
import base64
import json
import math
import re
import sys
import zipfile

ALGOS = [
    ("AES", re.compile(r"\bAES(?:/\w+){0,2}\b")),
    ("DES", re.compile(r"\bDES(?:ede)?(?:/\w+){0,2}\b")),
    ("RSA", re.compile(r"\bRSA(?:/\w+){0,2}\b")),
    ("Blowfish", re.compile(r"\bBlowfish(?:/\w+){0,2}\b")),
    ("ChaCha20", re.compile(r"\bChaCha20\b")),
    ("RC4", re.compile(r"\bARCFOUR\b|\bRC4\b")),
    ("MD5", re.compile(r"\bMD5\b")),
    ("SHA", re.compile(r"\bSHA(?:-?1|-?256|-?384|-?512)?\b")),
    ("Hmac", re.compile(r"\bHmac(SHA\d+)?\b")),
    ("SM2", re.compile(r"\bSM2\b")),
    ("SM3", re.compile(r"\bSM3\b")),
    ("SM4", re.compile(r"\bSM4\b")),
    ("Base64", re.compile(r"\bBase64\b")),
    ("Cipher", re.compile(r"javax/crypto/Cipher|javax\.crypto\.Cipher")),
    ("MessageDigest", re.compile(r"java/security/MessageDigest")),
    ("SecretKeySpec", re.compile(r"javax/crypto/spec/SecretKeySpec")),
    ("IvParameterSpec", re.compile(r"javax/crypto/spec/IvParameterSpec")),
    ("BouncyCastle", re.compile(r"org/bouncycastle/")),
]

MODES = re.compile(r"\b(?:AES|DES|RSA|Blowfish|SM4)/(ECB|CBC|CFB|OFB|CTR|GCM|NONE)/([A-Za-z0-9]+)\b")
KEYLIKE = re.compile(r"^[A-Za-z0-9+/=_\-]{16}$|^[A-Za-z0-9+/=_\-]{24}$|^[A-Za-z0-9+/=_\-]{32}$")
HEXKEY = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{48}$|^[0-9a-fA-F]{64}$")

SUSPECT_ASSET = re.compile(r"\.(dex|jar|dat|bin|enc|pak|payload|vdex)$", re.I)
NOISY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mp3", ".ogg", ".webm",
             ".zip", ".gz", ".br", ".ttf", ".otf", ".woff", ".woff2", ".sig", ".prof", ".so")


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


def dex_strings(buf):
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
        if end < 0 or end - pos < 4 or end - pos > 400:
            continue
        out.append(bytes(buf[pos:end]).decode("utf-8", "replace"))
    return out


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return round(e, 2)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "缺少 APK 路径"}))
        return
    path = sys.argv[1]
    limit = 20
    if "--limit" in sys.argv:
        try:
            limit = max(1, int(sys.argv[sys.argv.index("--limit") + 1]))
        except (IndexError, ValueError):
            pass

    strs = []
    algo_hit = {}
    modes = {}
    notes = []
    entropy_items = []
    suspect = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in sorted(x for x in z.namelist() if x.startswith("classes") and x.endswith(".dex")):
                with z.open(n) as f:
                    strs.extend(dex_strings(f.read()))
            # 资源侧：高熵文件、可疑 dex、非常大的 assets
            for info in z.infolist():
                name = info.filename
                if info.file_size < 2048 or name.endswith("/"):
                    continue
                is_asset = name.startswith("assets/") or name.startswith("res/raw/")
                if is_asset and SUSPECT_ASSET.search(name):
                    suspect.append({"name": name, "size": info.file_size})
                if is_asset and info.file_size >= 65536 and not name.lower().endswith(NOISY_EXT):
                    try:
                        with z.open(info) as f:
                            head = f.read(65536)
                        e = entropy(head)
                        if e >= 7.85:
                            entropy_items.append({"name": name, "size": info.file_size, "entropy": e})
                    except Exception:  # noqa: BLE001
                        continue
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}))
        return

    for name, pat in ALGOS:
        c = sum(1 for s in strs if pat.search(s))
        if c:
            algo_hit[name] = c
    for s in strs:
        for m in MODES.finditer(s):
            modes[f"{m.group(1)}/{m.group(2)}"] = modes.get(f"{m.group(1)}/{m.group(2)}", 0) + 1

    # 硬编码 key 候选：16/24/32 位，排除纯字母常见词
    keys = []
    for s in strs:
        if not (KEYLIKE.match(s) or HEXKEY.match(s)) or sum(c.isdigit() for c in s) < 2:
            continue
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", s) and s[0].isupper() and any(c.islower() for c in s):
            continue  # 像类名，不是 key
        if re.search(r"[a-z]{5,}", s) and not re.search(r"[A-Z]{3,}", s):
            continue
        if re.fullmatch(r"[A-Z0-9]+(?:_[A-Z0-9]+)+", s):
            continue  # 全大写常量名
        if "_" in s and re.search(r"[a-z]", s):
            continue  # 带下划线的驼峰名
        if "-" in s:
            continue  # kebab 名（前端打包产物）
        if re.fullmatch(r"[a-z][A-Za-z0-9]*", s) and any(c.isupper() for c in s):
            continue  # 小驼峰标识符  # 像单词/资源名，不是 key
        keys.append(s)
    keys = list(dict.fromkeys(keys))[:limit]

    if any(a in algo_hit for a in ("AES", "SM4", "DES", "RSA")):
        notes.append("代码里直接用到对称/非对称加密 API")
    if entropy_items:
        notes.append(f"assets 里有 {len(entropy_items)} 个高熵文件，可能是加密或压缩的载荷")
    if suspect:
        notes.append(f"发现 {len(suspect)} 个可疑资源（dex/dat/bin 之类）")

    print(json.dumps({
        "ok": True,
        "strings": len(strs),
        "algorithms": [{"name": k, "count": v} for k, v in sorted(algo_hit.items(), key=lambda kv: -kv[1])],
        "modes": [{"name": k, "count": v} for k, v in sorted(modes.items(), key=lambda kv: -kv[1])],
        "keys": keys,
        "entropy": sorted(entropy_items, key=lambda d: -d["entropy"])[:limit],
        "suspect": suspect[:limit],
        "notes": notes,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
