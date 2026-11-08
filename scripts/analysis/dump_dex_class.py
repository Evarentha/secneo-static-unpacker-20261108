#!/usr/bin/env python3
#
# Robust DEX Class Dumper
#
# Custom DEX parser that handles truncated map_list structures from packed APKs.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Parses DEX files directly from header offsets, tolerating missing or corrupt map_list structures that break standard analysis tools.
"""

"""
通用 DEX 类转储：给定类名，输出字段/方法/字符串/调用/常量。
用法: python dump_dex_class.py <dex> <类名含有的子串> ...
"""
import struct
import sys

DEXF = sys.argv[1] if len(sys.argv) > 1 else "app.dec.dex"
TARGETS = sys.argv[2:] or ["SimpleEncryptorUtil"]

buf = open(DEXF, "rb").read()
L = len(buf)
sids_size, sids_off = struct.unpack_from("<II", buf, 0x38)
tids_size, tids_off = struct.unpack_from("<II", buf, 0x40)
fids_size, fids_off = struct.unpack_from("<II", buf, 0x50)
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


def get_str(i):
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
    return get_str(struct.unpack_from("<I", buf, tids_off + t * 4)[0])


def method_ref(m):
    if m >= mids_size:
        return None
    o = mids_off + m * 8
    cls, proto, nm = struct.unpack_from("<HHI", buf, o)
    return ts(cls), get_str(nm)


def field_ref(f):
    if f >= fids_size:
        return None
    o = fids_off + f * 8
    cls, typ, nm = struct.unpack_from("<HHI", buf, o)
    return ts(cls), ts(typ), get_str(nm)


def parse_code(off):
    if not off or off >= L:
        return None
    registers, ins, outs, tries, dbg, size = struct.unpack_from("<HHHHII", buf, off)
    io = off + 16
    if io + size * 2 > L:
        return None
    return dict(regs=registers, ins=ins, tries=tries, size=size,
                insns=struct.unpack_from(f"<{size}H", buf, io))


INSN_SIZE = {0x02: 2, 0x03: 3, 0x05: 2, 0x06: 3, 0x08: 2, 0x09: 3,
             0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2,
             0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1F: 2, 0x20: 2, 0x22: 2, 0x23: 2,
             0x24: 3, 0x25: 3, 0x26: 3, 0x29: 2, 0x2A: 3, 0x2B: 3, 0x2C: 3,
             0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2}


def walk(ci):
    ins = ci["insns"]
    i = 0
    strs, calls, fields, consts = [], [], [], []
    while i < len(ins):
        u = ins[i]
        op = u & 0xFF
        hi = u >> 8
        n = INSN_SIZE.get(op, 1)
        if op == 0x1A and i + 1 < len(ins):
            s = get_str(ins[i + 1])
            if s: strs.append(s)
        elif op == 0x1B and i + 2 < len(ins):
            s = get_str(ins[i + 1] | (ins[i + 2] << 16))
            if s: strs.append(s)
        elif op in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78) and i + 1 < len(ins):
            r = method_ref(ins[i + 1])
            if r: calls.append(f"{r[0]}.{r[1]}")
            n = 3
        elif op in (0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
                    0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
                    0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D) and i + 1 < len(ins):
            r = field_ref(ins[i + 1])
            if r: fields.append(f"{r[1]} {r[2]}")
            n = 2
        elif op == 0x13:
            consts.append(f"0x{u & 0xFF:x} ({((u>>8)&0xFF)-256 if (u>>8)&0x80 else (u>>8)&0xFF})")
        elif op in (0x14, 0x17) and i + 1 < len(ins):
            v = ins[i + 1]
            consts.append(f"0x{v:x} ({v-65536 if v>=32768 else v})")
        elif op == 0x15 and i + 1 < len(ins):
            v = ins[i + 1]
            c = ((hi << 16) | v)
            consts.append(f"0x{c:x} ({c-2**32 if c>=2**31 else c})")
        i += n
    return strs, calls, fields, consts


for kw in TARGETS:
    print("\n" + "=" * 96)
    print(f"### 搜索: {kw}")
    print("=" * 96)
    found = 0
    for i in range(cds_size):
        base = cds_off + i * 32
        ci = struct.unpack_from("<I", buf, base)[0]
        name = ts(ci) or ""
        if kw not in name:
            continue
        found += 1
        (_, access, super_idx, if_off, src_idx, ann_off, cdoff, svoff) = \
            struct.unpack_from("<IIIIIIII", buf, base)
        print(f"\n─── [{i}] {name}   super={ts(super_idx)}  cdoff=0x{cdoff:x}")
        if not cdoff or cdoff >= L:
            print("    (no class_data)")
            continue
        o = cdoff
        sf, o = uleb(buf, o)
        inf, o = uleb(buf, o)
        dm, o = uleb(buf, o)
        vm, o = uleb(buf, o)
        # fields
        for cnt, lbl in ((sf, "static"), (inf, "instance")):
            idx = 0
            for _ in range(cnt):
                d, o = uleb(buf, o); idx += d
                acc, o = uleb(buf, o)
                fr = field_ref(idx)
                if fr: print(f"    field[{lbl}] {fr[1]} {fr[2]}")
        meths = []
        for cnt in (dm, vm):
            idx = 0
            for _ in range(cnt):
                d, o = uleb(buf, o); idx += d
                acc, o = uleb(buf, o)
                co, o = uleb(buf, o)
                meths.append((idx, acc, co))
        for midx, acc, co in meths:
            r = method_ref(midx)
            nm = r[1] if r else "?"
            st = "static " if acc & 0x8 else "       "
            print(f"\n    method {st}{nm}  @0x{co:x}")
            p = parse_code(co)
            if not p:
                continue
            strs, calls, flds, consts = walk(p)
            if strs: print(f"      STR  {strs}")
            if consts: print(f"      NUM  {consts[:12]}")
            if flds: print(f"      FLD  {list(dict.fromkeys(flds))[:10]}")
            cs = list(dict.fromkeys(calls))
            if cs: print(f"      CALL {cs[:14]}")
    if not found:
        print("  (未找到)")
