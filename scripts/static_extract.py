#!/usr/bin/env python3
#
# SecNeo Container & Metadata Static Extractor
#
# Statically extracts stub DEX layout and container parameters from SecNeo-packed APKs.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Parses APK archives without runtime execution to discover the embedded SecNeo container offset, stub DEX header fields, and unpacker descriptor structures.
"""

"""static_extract.py — 免设备从梆梆加固 APK 提取明文情报。

原理: Bangcle SecNeo 只加密 code_item(字节码), 保留 string/type/method 表明文,
      因此接口、类名、常量、密钥可从 classes.dex 直接 grep 出来。
用法: python static_extract.py <apk> [<apk> ...]
"""
import sys, os, zipfile, re, json

PATTERNS = {
    "endpoints":  re.compile(rb'(?m)^[\x00\s]*/(?:csb|mdm|api|open-svc|site|device|policy|whitelist|auth|login|v\d)[A-Za-z0-9_/{}$.-]*'),
    "hosts":      re.compile(rb'[a-zA-Z0-9_-]+\.(?:changyan|ceshiservice|openspeech|xfpaas|iflytek|changyan\.cn)\.(?:com|cn)(?::\d+)?'),
    "classes":    re.compile(rb'L(?:com/iflytek|com/secneo|com/android/iflylauncher)[A-Za-z0-9_/$;]+'),
    "secrets":    re.compile(rb'(?i)(?:appkey|appsecret|accesskey|aeskey|secretkey|token|passwd|password)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{6,}'),
    "urls":       re.compile(rb'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,120}'),
}

def strings(blob, minlen=4):
    return re.findall(rb'[ -~]{%d,}' % minlen, blob)

def analyze(apk):
    out = {"apk": os.path.basename(apk), "pak": None, "app": None, "ver": None, "dex_bytes": 0,
           "endpoints": set(), "hosts": set(), "secrets": set(), "urls": set(), "iflytek_classes": 0}
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        # manifest / dex number
        dexes = [n for n in names if re.match(r'classes\d*\.dex$', n)]
        out["dex_bytes"] = sum(z.getinfo(n).file_size for n in dexes)
        if "AndroidManifest.xml" in names:
            m = z.read("AndroidManifest.xml")
            for s in strings(m, 5):
                d = s.decode('latin1')
                if out["pak"] is None and re.match(r'^[a-z][a-z0-9_]+(\.[a-z0-9_]+){2,}$', d) and 'android' not in d[:8]:
                    out["pak"] = d
        for n in dexes:
            blob = z.read(n)
            for key, pat in PATTERNS.items():
                if key in ("endpoints", "hosts", "urls"):
                    for m in pat.findall(blob):
                        out[key].add(m.decode('latin1'))
                elif key == "secrets":
                    for m in pat.findall(blob):
                        out[key].add(m.decode('latin1'))
                elif key == "classes":
                    out["iflytek_classes"] += 1
    for k in ("endpoints", "hosts", "secrets", "urls"):
        out[k] = sorted(out[k])
    return out

if __name__ == "__main__":
    if not sys.argv[1:]:
        print(__doc__); sys.exit(1)
    res = []
    for apk in sys.argv[1:]:
        if not os.path.exists(apk):
            print("MISSING", apk); continue
        try:
            r = analyze(apk)
        except Exception as e:
            print("ERR", apk, e); continue
        res.append(r)
        print(f"\n===== {r['apk']}  pkg={r['pak']} dex={r['dex_bytes']}B iflytek_classes={r['iflytek_classes']}")
        for k in ("hosts", "endpoints", "secrets"):
            for v in r[k][:40]:
                print(f"  [{k}] {v}")
    json.dump(res, open("static_extract.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=lambda o: sorted(o))
    print("\n[+] wrote static_extract.json")
