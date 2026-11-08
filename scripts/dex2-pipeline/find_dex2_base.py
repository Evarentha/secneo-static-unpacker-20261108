#!/usr/bin/env python3
#
# DEX2 Base Address Locator
#
# Locates the base offset of the secondary DEX payload within container memory.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Scans memory offsets for secondary DEX header signatures and table anchors.
"""

"""Recover dex2's relocation base.

class_defs of dex2 live at 0x940A2C (validated: superclass=java/lang/Object etc).
Their class_data_off / interfaces_off / annotations_off values are NOT file
offsets -- they are offsets in dex2's own (standalone) coordinate space, because
a standalone dex2 would be: header 0x70, string_ids, type_ids, proto_ids,
field_ids, method_ids, class_defs, then data.

If the whole dex2 virtual image was placed at FILE_BASE, then
    file_offset = BASE + virtual_offset
We brute-force BASE with the class_data contiguity invariant:
    decode_class_data(BASE+v[i]) must end exactly at BASE+v[i+1]
(class_data_items of a dex are laid out contiguously in class_def order).
"""
import struct, sys

DEX = 'unpack/out/app.dec.dex'
d = open(DEX, 'rb').read()
L = len(d)
C = 0x940A2C; NC = 4233
cd = [struct.unpack_from('<8I', d, C + i * 32) for i in range(NC)]

def uleb(o):
    r = 0; s = 0
    for i in range(5):
        if o + i >= L: return None, 0
        b = d[o + i]; r |= (b & 0x7f) << s
        if not b & 0x80: return r, i + 1
        s += 7
    return None, 0

MAXV = 40000
def dec_class_data(o):
    """Return end offset or None. Validates every uleb against sane bounds."""
    vals = []
    for _ in range(4):
        v, n = uleb(o)
        if v is None or v > 3000: return None
        vals.append(v); o += n
    nf = vals[0] + vals[1]; nm = vals[2] + vals[3]
    for _ in range(nf):
        v, n = uleb(o)
        if v is None or v > MAXV: return None
        o += n
        v, n = uleb(o)
        if v is None or v > 0x200000: return None
        o += n
    for _ in range(nm):
        v, n = uleb(o)
        if v is None or v > MAXV: return None
        o += n
        v, n = uleb(o)
        if v is None or v > 0x200000: return None
        o += n
        v, n = uleb(o)          # code_off
        if v is None or v > L: return None
        o += n
    return o

def score(base, n=60):
    good = tot = 0
    for i in range(n):
        v = cd[i][6]
        if v == 0: continue
        e = dec_class_data(base + v)
        nxt = cd[i + 1][6] if i + 1 < NC else None
        tot += 1
        if e is not None and nxt is not None and e == base + nxt:
            good += 1
    return good, tot

if __name__ == '__main__':
    lo, hi = 0x800000, 0x9A0000
    best = []
    for base in range(lo, hi):
        g, t = score(base)
        if g >= t * 0.8 and t:
            best.append((g, base))
    best.sort(reverse=True)
    print(f"candidates (top 10) over [{hex(lo)},{hex(hi)}):")
    for g, b in best[:10]:
        print(f"  base=0x{b:X} score={g}/60")
    if not best:
        print("  NONE")
