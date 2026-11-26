#!/usr/bin/env python3
"""APK 体检：只用标准库解析 manifest(AXML)、dex 头、签名块、so 清单。"""
import hashlib
import json
import struct
import sys
import zipfile

DANGEROUS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS", "android.permission.GET_ACCOUNTS",
    "android.permission.QUERY_ALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS", "android.permission.ACCESS_MEDIA_LOCATION",
}

PACKERS = [
    (("libjiagu.so", "libjiagu_ls.so", "libjiagu_a64.so"), "360 加固"),
    (("libshell.so", "libshellx.so", "libtosprotection.so"), "腾讯乐固"),
    (("libDexHelper.so", "libDexHelper-x86.so"), "梆梆加固"),
    (("libnesec.so", "libnetease.so"), "网易易盾"),
    (("libbaiduprotect.so",), "百度加固"),
    (("libmobisec.so",), "阿里聚安全"),
    (("libexec.so", "libexecmain.so"), "阿里加固"),
    (("libapkprotect.so",), "apkprotect"),
    (("libSecShell.so", "libSecShellX.so"), "腾讯御安全"),
]

FRAMEWORKS = [
    (("libflutter.so",), "Flutter"),
    (("libhermes.so", "libhermes-executor.so"), "React Native"),
    (("libunity.so",), "Unity"),
    (("libmonodroid.so", "libmonosgen-2.0.so"), "Xamarin"),
    (("libcocos2djs.so", "libcocos2d.so"), "Cocos"),
]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def read_string_pool(buf, base):
    """返回 (strings, chunk_size)。"""
    header_size = u16(buf, base + 2)
    chunk_size = u32(buf, base + 4)
    count = u32(buf, base + 8)
    flags = u32(buf, base + 16)
    strings_start = u32(buf, base + 20)
    utf8 = bool(flags & 0x100)
    offsets = [u32(buf, base + header_size + 4 * i) for i in range(count)]
    data0 = base + strings_start
    out = []
    for off in offsets:
        p = data0 + off
        try:
            if utf8:
                n = buf[p]
                p += 2 if n & 0x80 else 1
                n = buf[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[p + 1]
                    p += 2
                else:
                    p += 1
                out.append(buf[p:p + n].decode("utf-8", "replace"))
            else:
                n = u16(buf, p)
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | u16(buf, p)
                    p += 2
                out.append(buf[p:p + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out, chunk_size


def parse_axml(data):
    """解析 binary XML，返回 (package_attrs, elements)。elements 为 [(tag, {attr: value})]。"""
    if len(data) < 8 or u16(data, 0) != 0x0003:
        return {}, []
    strings, _ = [], []
    root_attrs, elements = {}, []
    ns = ""
    p = u16(data, 2)
    end = min(len(data), u32(data, 4))
    strings = []
    resmap = []
    while p + 8 <= end:
        ctype = u16(data, p)
        header = u16(data, p + 2)
        size = u32(data, p + 4)
        if size < 8:
            break
        if ctype == 0x0001:
            strings, _ = read_string_pool(data, p)
        elif ctype == 0x0180:
            n = (size - header) // 4
            resmap = [u32(data, p + header + 4 * i) for i in range(n)]
        elif ctype == 0x0102:
            name_idx = u32(data, p + 20)
            attr_start = u16(data, p + 24)
            attr_count = u16(data, p + 28)
            tag = strings[name_idx] if name_idx < len(strings) else ""
            attrs = {}
            for i in range(attr_count):
                a = p + header + attr_start + i * 20
                if a + 20 > end:
                    break
                aname_idx = u32(data, a + 4)
                raw = u32(data, a + 8)
                dtype = data[a + 15]
                dval = u32(data, a + 16)
                aname = strings[aname_idx] if aname_idx < len(strings) else ""
                rid = resmap[aname_idx] if aname_idx < len(resmap) else 0
                if dtype == 0x03 and dval < len(strings):
                    val = strings[dval]
                elif dtype == 0x12:
                    val = bool(dval)
                elif dtype == 0x10:
                    val = dval
                elif raw != 0xFFFFFFFF and raw < len(strings):
                    val = strings[raw]
                else:
                    val = dval
                if rid:
                    attrs["#%08x" % rid] = val
                attrs[aname] = val
            if tag == "manifest" and not root_attrs:
                root_attrs = attrs
            elements.append((tag, attrs))
        elif ctype == 0x0103:
            pass
        p += size
    return root_attrs, elements


def signing_schemes(fh, size):
    """只读尾部，避免把几百 MB 的 APK 装进内存。"""
    schemes = []
    try:
        tail_len = min(size, 128 * 1024)
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        idx = tail.rfind(b"PK\x05\x06")
        if idx < 0:
            return schemes
        cd_off = u32(tail, idx + 16)
        span = min(cd_off, 2 * 1024 * 1024)
        fh.seek(cd_off - span)
        blk = fh.read(span)
        if len(blk) < 24 or blk[-16:] != b"APK Sig Block 42":
            return schemes
        total = struct.unpack_from("<Q", blk, len(blk) - 24)[0]
        start = max(0, len(blk) - (total + 8))
        p = start + 8
        while p + 12 <= len(blk) - 24:
            pair_len = struct.unpack_from("<Q", blk, p)[0]
            pid = u32(blk, p + 8)
            if pid == 0x7109871A:
                schemes.append("v2")
            elif pid == 0xF05368C0:
                schemes.append("v3")
            elif pid == 0x1B93AD61:
                schemes.append("v3.1")
            if pair_len <= 0:
                break
            p += 8 + pair_len
    except Exception:
        pass
    return schemes


def analyze(path):
    info = {"ok": True, "path": path, "name": path.rsplit("/", 1)[-1]}
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        size = fh.tell()
        info["size"] = size
        info["sha256"] = digest.hexdigest()
        schemes = signing_schemes(fh, size)
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        try:
            mf = z.read("AndroidManifest.xml")
        except KeyError:
            return {"ok": False, "error": "没有 AndroidManifest.xml，可能不是完整 APK"}
    root, elements = parse_axml(mf)
    get = lambda *keys: next((root[k] for k in keys if k in root), None)
    info["package"] = get("package") or "?"
    info["versionName"] = get("#0101021c", "versionName")
    info["versionCode"] = get("#0101021b", "versionCode")
    uses_sdk, app_attrs = {}, {}
    for tag, attrs in elements:
        if tag == "uses-sdk" and not uses_sdk:
            uses_sdk = attrs
        elif tag == "application" and not app_attrs:
            app_attrs = attrs
    pick = lambda d, *keys: next((d[k] for k in keys if k in d), None)
    info["minSdk"] = pick(uses_sdk, "#0101020c", "minSdkVersion")
    info["targetSdk"] = pick(uses_sdk, "#01010270", "targetSdkVersion")
    info["compileSdk"] = get("#01010501", "compileSdkVersion")
    info["debuggable"] = bool(pick(app_attrs, "#0101000f", "debuggable"))
    info["allowBackup"] = pick(app_attrs, "#01010280", "allowBackup")
    info["cleartext"] = pick(app_attrs, "#010104ec", "usesCleartextTraffic")
    if isinstance(info["versionName"], int):
        info["versionName"] = None
    if info["versionName"] is not None and not isinstance(info["versionName"], str):
        info["versionName"] = None
    if info["versionName"] and info["versionName"].startswith("@"):
        info["versionName"] = info["versionName"] + "(资源引用)"

    perms, counts, flags = [], {"activity": 0, "service": 0, "receiver": 0, "provider": 0}, []
    exported = 0
    for tag, attrs in elements:
        if tag == "uses-permission" or tag == "uses-permission-sdk-23":
            name = attrs.get("#01010003") or attrs.get("name")
            if isinstance(name, str) and name not in perms:
                perms.append(name)
        elif tag in counts:
            counts[tag] += 1
            if attrs.get("#01010010") is True or attrs.get("exported") is True:
                exported += 1
            if tag in ("activity", "receiver", "service"):
                for key in ("intent-filter",):
                    pass
    info["perms"] = perms
    info["dangerPerms"] = [p for p in perms if p in DANGEROUS]
    info["counts"] = counts
    info["exported"] = exported

    dex = sorted(n for n in names if n.startswith("classes") and n.endswith(".dex"))
    info["dex"] = len(dex)
    classes = 0
    try:
        with zipfile.ZipFile(path) as z:
            for n in dex[:40]:
                head = z.read(n)[:112]
                if len(head) >= 112 and head[:4] == b"dex\n":
                    classes += u32(head, 96)
    except Exception:
        pass
    info["dexClasses"] = classes

    libs = sorted({n for n in names if n.startswith("lib/") and n.endswith(".so")})
    abis = sorted({n.split("/")[1] for n in libs if n.count("/") >= 2})
    info["abis"] = abis
    info["soCount"] = len(libs)
    sobase = {n.rsplit("/", 1)[-1] for n in libs}
    info["packers"] = [name for sig, name in PACKERS if sobase & set(sig)]
    frameworks = [name for sig, name in FRAMEWORKS if sobase & set(sig)]
    if "assets/index.android.bundle" in names:
        frameworks.append("React Native")
    if "assets/flutter_assets" in " ".join(names):
        frameworks.append("Flutter")
    if any(n.startswith("assets/www/") for n in names):
        frameworks.append("Cordova/WebView")
    info["frameworks"] = sorted(set(frameworks))
    info["junk"] = [n for n in names if n.endswith((".apk", ".zip", ".so.1"))][:5]

    mitm = [n for n in names if n.lower().endswith((".pem", ".crt", ".cer", ".p12", ".bks"))]
    info["certs"] = mitm[:5]
    if not schemes:
        schemes = ["v1"] if any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names) else []
    info["sig"] = schemes
    return info


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "缺少 APK 路径"}))
        return 1
    try:
        print(json.dumps(analyze(sys.argv[1]), ensure_ascii=False))
    except Exception as exc:  # 出错也要给 App 一个能读的 JSON
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
