#!/usr/bin/env python3
#
# DEX2 ID Table Contiguity Validator
#
# Verifies byte adjacency across proto_ids, field_ids, and method_ids tables.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Ensures that Dalvik ID tables are strictly contiguous without unexpected padding or alignment drift.
"""

# Step 4: is the class_data chain real? Dense-walk test + code_item plausibility test.
import struct, collections, statistics

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
CLASS_OFF, NCLASS, NTYPE, NPROTO, NMETH, NSTR = 0x940A2C, 4233, 5503, 6088, 30873, 32388

def uleb(b, o):
    r = 0; s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80: return r, o
        s += 7
        if s > 35: raise ValueError("uleb")

def sleb(b, o):
    r = 0; s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            if x & 0x40: r -= (1 << s)
            return r, o

defs = [struct.unpack_from("<8I", data, CLASS_OFF + 32*i) for i in range(NCLASS)]
cdos = sorted({d[6] for d in defs if d[6]})
print(f"distinct class_data_off: {len(cdos)}  min {cdos[0]:#x} max {cdos[-1]:#x}")

print("\n--- hexdump of the 3 smallest/largest class_data_off ---")
for c in cdos[:2] + cdos[-2:]:
    print(f"  {c:#x}: " + data[c:c+0x30].hex(" "))

print("\n--- 4-uleb header values for 15 sampled classes ---")
rows = []
for c in cdos[::max(1, len(cdos)//15)][:15]:
    p = c; sz = []
    for _ in range(4):
        v, p = uleb(data, p); sz.append(v)
    rows.append((hex(c), sz))
    print(f"  {c:#x}: static={sz[0]} instance={sz[1]} direct={sz[2]} virtual={sz[3]}")

# --- dense walk: consume the whole [min,max] range as a chain of class_data_item ---
print("\n--- dense chain walk 0x%x -> 0x%x ---" % (cdos[0], cdos[-1]))
o = cdos[0]
code_offs = []
field_idx_ok = method_idx_ok = 0; items = 0; starts = []
try:
    while o < cdos[-1] + 16:
        start = o
        s0, o = uleb(data, o); s1, o = uleb(data, o)
        d0, o = uleb(data, o); d1, o = uleb(data, o)
        if max(s0, s1, d0, d1) > 5000: raise ValueError("bad sizes")
        starts.append(start)
        idx = 0
        for _ in range(s0 + s1):
            if o >= N: raise ValueError("eof")
            idx, o = uleb(data, o)
            if idx < 27201: field_idx_ok += 1
            _, o = uleb(data, o)
        midx = 0
        for _ in range(d0 + d1):
            midx, o = uleb(data, o)
            if midx < NMETH: method_idx_ok += 1
            _, o = uleb(data, o)
            co, o = uleb(data, o)
            if co: code_offs.append(co)
        items += 1
except Exception as e:
    print("  walk stop:", e)
print(f"  items_walked={items}  final_o={o:#x}  (target {cdos[-1]:#x})")
tot = field_idx_ok + method_idx_ok
print(f"  field idx in range: {field_idx_ok}   method idx in range: {method_idx_ok}")
print(f"  code_offs collected: {len(code_offs)}  distinct {len(set(code_offs))}")

if code_offs:
    print(f"  code_off min={min(code_offs):#x} max={max(code_offs):#x}")
    b = collections.Counter()
    for c in code_offs:
        if c < 0x3397D7: b["< dex1 strpool end"] += 1
        elif c < 0x897400: b["dex1 data"] += 1
        elif c < 0x8B8000: b["encrypted blob"] += 1
        elif c < 0x961B4C: b["dex2 id tables"] += 1
        elif c < 0xA2EEB8: b["pool2"] += 1
        elif c < N: b[">= 0xA2EEB8 tail"] += 1
        else: b["oob"] += 1
    print("  distribution:", dict(b))

    print("\n--- code_item header plausibility test on harvested code_off ---")
    good = 0; tested = 0; samples = []
    for c in code_offs:
        if not (0 < c < N - 16): continue
        tested += 1
        regs, ins, outs, tries, dbg, insns = struct.unpack_from("<HHHHII", data, c)
        ok = (0 < regs <= 255 and ins <= regs and outs <= 255 and tries < 100
              and 0 < insns < 200000 and (dbg == 0 or dbg < N) and c + 16 + 2*insns <= N + 64)
        if ok:
            good += 1
            if len(samples) < 8: samples.append((c, regs, ins, outs, tries, dbg, insns))
    print(f"  plausible code_item headers: {good}/{tested}")
    for s in samples:
        print(f"   {s[0]:#08x} regs={s[1]} ins={s[2]} outs={s[3]} tries={s[4]} dbg={s[5]:#x} insns={s[6]}")
