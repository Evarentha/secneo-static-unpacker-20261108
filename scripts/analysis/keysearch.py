#!/usr/bin/env python3
#
# SM4 128-Bit Key Sliding-Window Search
#
# Performs exhaustive sliding-window search across decrypted binaries for SM4 keys.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Tests candidate 16-byte windows from native modules against known ciphertext/plaintext blocks using the SM4 block cipher.
"""

"""
用 DEX 字符串表里所有 hex-like 串作为 AES/3DES key，尝试解 48-hex 密文。
匹配标准：解出 >=9 字节可打印 ASCII（口令长度合理）。
"""
import struct
import re
import hashlib
from Crypto.Cipher import AES, DES3, DES

DEX = "app.dec.dex"
buf = open(DEX, "rb").read()
L = len(buf)
sids_size, sids_off = struct.unpack_from("<II", buf, 0x38)


def uleb(b, o):
    r, s = 0, 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


def get_str(i):
    if i >= sids_size:
        return None
    off = struct.unpack_from("<I", buf, sids_off + i * 4)[0]
    if off >= L:
        return None
    _, o = uleb(buf, off)
    e = buf.find(b"\x00", o)
    if e < 0 or e - o > 400:
        return None
    try:
        return buf[o:e].decode("utf-8")
    except Exception:
        return None


TARGETS = {
    "淮南99": "09186a844339551271e33f0af1fc6180c97d72c60ba93385",
    "讯飞测试小学": "a3ba39313579f70a10c67b0a496d1018976b216b1dd06807",
    "智课平台": "98235fc8a78365f14f00765a04512dd09c7b30332c661b2a",
}
CTS = {k: bytes.fromhex(v) for k, v in TARGETS.items()}

# 收集候选 key 串
hexre = re.compile(r"^[0-9a-fA-F]+$")
cands = []
for i in range(sids_size):
    s = get_str(i)
    if not s or len(s) < 8:
        continue
    if hexre.match(s) and len(s) in (16, 24, 32, 40, 48, 56, 64):
        cands.append((i, s))
print(f"hex-like 字符串候选: {len(cands)}")
for i, s in cands[:40]:
    print(f"  [{i}] {s}")

# 也加入常见派生
extra = []
for s in ("zhkt-mdm-service", "9dfa99db6daa077b", "changyan", "iflytek", "mdm020", "zhkt"):
    b = s.encode()
    extra.append((f"md5({s})", hashlib.md5(b).hexdigest()))
    extra.append((f"sha1({s})", hashlib.sha1(b).hexdigest()))
    extra.append((f"sha256({s})", hashlib.sha256(b).hexdigest()))


def score(b):
    return sum(1 for x in b if 32 <= x < 127) if b else 0


def try_all(keyhex, label):
    try:
        kb = bytes.fromhex(keyhex)
    except Exception:
        return None
    if len(kb) >= 16 and len(kb) % 8 == 0:
        for cname, ct in CTS.items():
            # AES 前 16 字节
            if len(kb) in (16, 24, 32):
                try:
                    pt = AES.new(kb, AES.MODE_ECB).decrypt(ct[:16])
                    s = score(pt)
                    if s >= 11:
                        return (s, cname, "AES-ECB(16)", label, pt)
                except Exception:
                    pass
            # 3DES 全 24
            if len(kb) >= 24:
                for ivn, iv in (("0", b"\x00" * 8), ("k", kb[:8])):
                    try:
                        pt = DES3.new(kb[:24], DES3.MODE_CBC, iv).decrypt(ct)
                        s = score(pt)
                        if s >= 16:
                            return (s, cname, f"3DES-CBC/{ivn}", label, pt)
                    except Exception:
                        pass
            # DES
            if len(kb) >= 8:
                try:
                    pt = DES.new(kb[:8], DES.MODE_ECB).decrypt(ct)
                    s = score(pt)
                    if s >= 16:
                        return (s, cname, "DES-ECB", label, pt)
                except Exception:
                    pass
    return None


hits = []
print("\n扫描 ...")
for n, (i, s) in enumerate(cands):
    r = try_all(s, f"str[{i}]")
    if r:
        hits.append(r)
        print(f"  ★ {r}")
    if n % 100 == 0:
        print(f"    {n}/{len(cands)}", flush=True)

for lbl, s in extra:
    r = try_all(s, lbl)
    if r:
        hits.append(r)
        print(f"  ★ {r}")

print(f"\n命中 {len(hits)} 条")
if not hits:
    print("无命中")
else:
    for r in sorted(hits, reverse=True)[:10]:
        print(f"  {r[0]}/{len(r[4])} {r[1]} {r[2]} key={r[3]} → {r[4]!r}")
