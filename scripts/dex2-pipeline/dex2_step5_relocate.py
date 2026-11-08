#!/usr/bin/env python3
#
# DEX2 Table Relocation Calculator
#
# Computes file-offset adjustment deltas for fragmented memory segments.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Calculates base relocation offsets needed when reassembling in-memory DEX slices back into linear file layouts.
"""

# Step 5: hypothesis — dex2 data section (class_data + code) was RELOCATED to the tail
# [0xA2EEB8, EOF). class_data_off values still carry old-file coordinates.
# Tests: (a) literal byte-pattern search for the 0x406090 block elsewhere,
#        (b) delta-corrected chain validity, (c) gap statistics.
import struct, collections

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
CLASS_OFF, NCLASS = 0x940A2C, 4233
TAIL = 0xA2EEB8

defs = [struct.unpack_from("<8I", data, CLASS_OFF + 32*i) for i in range(NCLASS)]
cdos = sorted({d[6] for d in defs if d[6]})
print(f"distinct class_data_off: {len(cdos)}  min {cdos[0]:#x} max {cdos[-1]:#x}  span {cdos[-1]-cdos[0]:#x}")

print("\n--- gap statistics between consecutive class_data_off ---")
gaps = [cdos[i+1]-cdos[i] for i in range(len(cdos)-1)]
print("  min", min(gaps), "max", max(gaps), "median", sorted(gaps)[len(gaps)//2],
      "mean %.1f" % (sum(gaps)/len(gaps)))
print("  gap histogram (<=8, <=24, <=64, <=256, >256):",
      sum(1 for g in gaps if g <= 8), sum(1 for g in gaps if 8 < g <= 24),
      sum(1 for g in gaps if 24 < g <= 64), sum(1 for g in gaps if 64 < g <= 256),
      sum(1 for g in gaps if g > 256))

print("\n--- (a) literal search for the 0x406090 block inside the tail ---")
blk = data[0x406090:0x406090+64]
idx = data.find(blk, TAIL)
print(f"  64B block @0x406090 found in tail at: {idx:#x}" if idx >= 0 else "  not found in tail")
blk2 = data[0x444af8:0x444af8+48]
idx2 = data.find(blk2, TAIL)
print(f"  48B block @0x444AF8 found in tail at: {idx2:#x}" if idx2 >= 0 else "  not found in tail")
# also global
print("  global hits 0x406090-block:", [hex(i) for i in [data.find(blk)] if i >= 0])

def uleb(b, o, n=N):
    r = 0; s = 0
    while True:
        if o >= n: raise ValueError("eof")
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80: return r, o
        s += 7
        if s > 35: raise ValueError("uleb")

def chain_score(base, delta, limit=800):
    """shift all class_data_off by delta, then test density/legality of the chain."""
    starts = [c + delta for c in cdos if 0 <= c + delta < N]
    starts.sort()
    exact = 0; sane = 0; tested = 0; end_hits = 0
    for i in range(min(limit, len(starts)-1)):
        o = starts[i]; tested += 1
        try:
            p = o
            sz = []
            for _ in range(4):
                v, p = uleb(data, p); sz.append(v)
            if max(sz) > 4000: continue
            sane += 1
            for _ in range(sz[0]+sz[1]):
                _, p = uleb(data, p); _, p = uleb(data, p)
            for _ in range(sz[2]+sz[3]):
                _, p = uleb(data, p); _, p = uleb(data, p); _, p = uleb(data, p)
            if p == starts[i+1]: exact += 1
            elif abs(p - starts[i+1]) <= 3: end_hits += 1
        except Exception:
            pass
    return tested, sane, exact, end_hits

print("\n--- (b) chain validity vs delta ---")
cands = [0, TAIL - cdos[0], -0x1000, 0x1000, TAIL - 0x406090,
         TAIL - cdos[0] + 0x1000, TAIL - cdos[0] - 0x1000]
for d in sorted(set(cands)):
    t, s, ex, near = chain_score(0, d)
    print(f"  delta={d:+#x} -> tested {t}, sane-hdr {s}, exact-end {ex}, end±3 {near}")

print("\n--- (c) what does the head of the tail look like? ---")
for o in (TAIL, TAIL+0x40, TAIL+0x100, TAIL+0x400):
    print(f"  {o:#08x}: " + data[o:o+48].hex(" "))
print("\n--- and the class_data min for comparison ---")
print(f"  0x406090: " + data[0x406090:0x406090+48].hex(" "))
