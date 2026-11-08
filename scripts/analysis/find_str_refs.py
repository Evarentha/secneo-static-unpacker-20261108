#!/usr/bin/env python3
#
# DEX String Reference Cross-Scanner
#
# Finds all method code_items referencing a specified string index.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Scans bytecode across all classes to locate references to a target string ID.
"""

"""
在 DEX 里找引用指定字符串的方法：定位 getLoginPwd / saveLoginPwd 的调用点。
"""
import struct
import sys

DEX = "app.dec.dex"
NEEDLES = ["getLoginPwd", "saveLoginPwd", "loginPwd", "isMessageLogining"]

buf = open(DEX, "rb").read()
L = len(buf)
sids_size, sids_off = struct.unpack_from("<II", buf, 0x38)
tids_size, tids_off = struct.unpack_from("<II", buf, 0x40)
mids_size, mids_off = struct.unpack_from("<II", buf, 0x58)
cds_size, cds_off = struct.unpack_from("<II", buf, 0x60)


def uleb(b, o):
    r, s = 0, 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


def gs(i):
    if i >= sids_size:
        return None
    off = struct.unpack_from("<I", buf, sids_off + i * 4)[0]
    if off >= L:
        return None
    _, o = uleb(buf, off)
    e = buf.find(b"\x00", o)
    if e < 0 or e - o > 600:
        return None
    try:
        return buf[o:e].decode("utf-8")
    except Exception:
        return None


def ts(t):
    if t >= tids_size:
        return None
    return gs(struct.unpack_from("<I", buf, tids_off + t * 4)[0])


def mref(m):
    if m >= mids_size:
        return None
    o = mids_off + m * 8
    c, p, n = struct.unpack_from("<HHI", buf, o)
    return ts(c), gs(n)


# 1) 找字符串索引
targets = {}
for i in range(sids_size):
    s = gs(i)
    if s and s in NEEDLES:
        targets[s] = i
print("字符串索引:", targets)
if not targets:
    print("未找到"); sys.exit(0)

target_idx = set(targets.values())

# 2) 遍历所有 class_data → 所有 code_item → 扫 const-string
hits = []
for ci in range(cds_size):
    base = cds_off + ci * 32
    cidx = struct.unpack_from("<I", buf, base)[0]
    cname = ts(cidx) or ""
    cdoff = struct.unpack_from("<I", buf, base + 0x18)[0]
    if not cdoff or cdoff >= L:
        continue
    o = cdoff
    try:
        sf, o = uleb(buf, o)
        inf, o = uleb(buf, o)
        dm, o = uleb(buf, o)
        vm, o = uleb(buf, o)
        # skip fields
        for cnt in (sf, inf):
            idx = 0
            for _ in range(cnt):
                d, o = uleb(buf, o); idx += d
                a, o = uleb(buf, o)
        meths = []
        for cnt in (dm, vm):
            idx = 0
            for _ in range(cnt):
                d, o = uleb(buf, o); idx += d
                a, o = uleb(buf, o)
                co, o = uleb(buf, o)
                meths.append((idx, co))
    except Exception:
        continue

    for midx, co in meths:
        if not co or co >= L:
            continue
        try:
            regs, ins, outs, tries, dbg, sz = struct.unpack_from("<HHHHII", buf, co)
            io = co + 16
            if io + sz * 2 > L:
                continue
            words = struct.unpack_from(f"<{sz}H", buf, io)
        except Exception:
            continue
        found = False
        callers = []
        i = 0
        while i < len(words):
            u = words[i]
            op = u & 0xFF
            if op == 0x1A and i + 1 < len(words):
                if words[i + 1] in target_idx:
                    found = True
                i += 2
                continue
            if op == 0x1B and i + 2 < len(words):
                sidx = words[i + 1] | (words[i + 2] << 16)
                if sidx in target_idx:
                    found = True
                i += 3
                continue
            if op in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78) and i + 1 < len(words):
                r = mref(words[i + 1])
                if r:
                    callers.append(f"{r[0]}.{r[1]}")
                i += 3
                continue
            if op == 0x18:
                i += 5; continue
            if op in (0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C, 0xFC, 0xFD):
                i += 3; continue
            if op in (0x02, 0x05, 0x08, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1C,
                      0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x29, 0xFE, 0xFF):
                i += 2; continue
            if op == 0x03:
                i += 3; continue
            i += 1
        if found:
            mr = mref(midx)
            hits.append((cname, f"{mr[0]}.{mr[1]}" if mr else "?", list(dict.fromkeys(callers))[:8]))

print(f"\n引用到目标字符串的方法: {len(hits)}\n")
for cname, meth, calls in hits:
    print(f"═══ {cname}")
    print(f"    {meth}")
    for c in calls:
        print(f"      → {c}")
    print()
