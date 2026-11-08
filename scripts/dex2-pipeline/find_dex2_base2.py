#!/usr/bin/env python3
#
# DEX2 Secondary Base Address Locator
#
# Alternative base offset locator using method table heuristic signatures.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Refined search script for secondary DEX base alignment.
"""

"""Brute-force the dex2 data-section relocation base.

class_defs (0x940A2C) carry class_data_off values 0x406090..0x444B34 that are
NOT file offsets: they are offsets in dex2's virtual (standalone) image.
Assume a single additive relocation: file = BASE + virtual.
Oracle: class_data_items are laid out contiguously in class_def order, so
    dec(BASE+v[i]) == BASE+v[i+1]
We test the first 8 items; a wrong BASE dies on the first item.
"""
import struct, sys

d = open('unpack/out/app.dec.dex', 'rb').read()
L = len(d)
C, NC = 0x940A2C, 4233
cd = [struct.unpack_from('<8I', d, C + i * 32) for i in range(NC)]
V = [x[6] for x in cd]
VMIN, VMAX = min(v for v in V if v), max(V)
print(f"class_data_off count={sum(1 for v in V if v)} min=0x{VMIN:X} max=0x{VMAX:X} span=0x{VMAX-VMIN:X}", file=sys.stderr)

def uleb(o):
    r = 0; s = 0
    for i in range(5):
        b = d[o + i]; r |= (b & 0x7f) << s
        if not b & 0x80: return r, i + 1
        s += 7
        if o + i >= L: return None, 0
    return None, 0

def dec(o):
    if o < 0 or o + 8 > L: return None
    vals = []
    for _ in range(4):
        v, n = uleb(o)
        if v is None or v > 2000: return None
        vals.append(v); o += n
    nf = vals[0] + vals[1]; nm = vals[2] + vals[3]
    if nf > 4000 or nm > 4000: return None
    for _ in range(nf):
        v, n = uleb(o)
        if v is None or v > 40000: return None
        o += n
        v, n = uleb(o)
        if v is None or v > 0x300000: return None
        o += n
    for _ in range(nm):
        v, n = uleb(o)
        if v is None or v > 40000: return None
        o += n
        v, n = uleb(o)
        if v is None or v > 0x300000: return None
        o += n
        v, n = uleb(o)              # code_off
        if v is None or v > 0x600000: return None
        o += n
        if o > L: return None
    return o

if __name__ == '__main__':
    lo = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x400000
    hi = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x8E0000
    first = V[0]
    nxt = V[1]
    hits = []
    for base in range(lo, hi):
        s = base + first
        e = dec(s)
        if e is None or e != base + nxt:
            continue
        # confirm with next 6 links
        ok = True
        for k in range(1, 7):
            if k + 1 >= NC: break
            e2 = dec(base + V[k])
            if e2 is None or e2 != base + V[k + 1]:
                ok = False; break
        if ok:
            hits.append(base)
    print(f"bases in [0x{lo:X},0x{hi:X}): {len(hits)}")
    for b in hits[:20]:
        print(f"  BASE=0x{b:X}")
