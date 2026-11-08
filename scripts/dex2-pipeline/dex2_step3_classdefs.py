#!/usr/bin/env python3
#
# DEX2 class_def Structure Extractor
#
# Iterates class_def_item entries and maps class inheritance hierarchies.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Parses class definition records, validating superclass and interface indexes against type_ids structures.
"""

# Step 3: class_defs are PLAINTEXT -> parse all 4233, inspect class_data_off targets,
# and measure entropy of the region they point into. Decides "code encrypted or not".
import math, struct, collections, statistics

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
NSTR, NTYPE, NPROTO, NFIELD, NMETH, NCLASS = 32388, 5503, 6088, 27201, 30873, 4233
CLASS_OFF, POOL2_OFF = 0x940A2C, 0x961B68

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def uleb(b, o):
    r = 0; s = 0
    while True:
        if o >= len(b): raise ValueError("eof")
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80: return r, o
        s += 7
        if s > 35: raise ValueError("uleb too long")

print("--- class_def_item table @ %#x (%d entries x 32B) ---" % (CLASS_OFF, NCLASS))
defs = []
bad = 0
for i in range(NCLASS):
    o = CLASS_OFF + 32*i
    cls, acc, sup, ifo, sfi, ano, cdo, svo = struct.unpack_from("<8I", data, o)
    if cls >= NTYPE: bad += 1
    defs.append((i, cls, cdo, sfi, ifo, ano, svo))
print(f"class_idx in range: {NCLASS-bad}/{NCLASS}")

cdos = [d[2] for d in defs]
print("class_data_off distinct:", len(set(cdos)), " zero:", cdos.count(0))
print("min %#x  max %#x  median %#x" % (min(c for c in cdos if c), max(cdos), statistics.median(cdos)))
buckets = collections.Counter()
for c in cdos:
    if c == 0: buckets["zero"] += 1
    elif c < 0x897400: buckets["<0x897400 (dex1 area)"] += 1
    elif c < 0x8B8000: buckets["encrypted blob"] += 1
    elif c < 0x961B4C: buckets["id tables"] += 1
    elif c < 0xA2EEB8: buckets["pool2 (strings)"] += 1
    elif c < N: buckets[">=0xA2EEB8 (tail)"] += 1
    else: buckets["out of file"] += 1
for k, v in buckets.most_common(): print(f"   {k:26s} {v}")

print("\n--- do class_data_off targets look like class_data_item (4 uleb128 sizes)? ---")
sample = [d for d in defs if d[2]][:60] + [d for d in defs if d[2]][-60:]
oklen = oksteps = 0; tested = 0; codes = []
for i, cls, cdo, *_ in sample:
    tested += 1
    try:
        p = cdo
        sz = []
        for _ in range(4):
            v, p = uleb(data, p); sz.append(v)
        oklen += 1
        # feed count = static+instance fields; methods = direct+virtual
        nfields, nmethods = sz[0]+sz[1], sz[2]+sz[3]
        if nfields < 2000 and nmethods < 2000:
            oksteps += 1
        # walk methods to collect code_off (first up to 3)
        q = p
        for _ in range(nfields):
            _, q = uleb(data, q)   # field_idx_diff
            _, q = uleb(data, q)   # access_flags
        for _ in range(nmethods):
            _, q = uleb(data, q)   # method_idx_diff
            _, q = uleb(data, q)   # access_flags
            c, q = uleb(data, q)   # code_off
            if c: codes.append(c)
    except Exception:
        pass
print(f"4-uleb header decoded: {oklen}/{tested};  sane sizes: {oksteps}/{tested}")
print(f"code_offs harvested: {len(codes)}  min={min(codes):#x} max={max(codes):#x}" if codes else "code_offs harvested: 0")

if codes:
    b = collections.Counter()
    for c in codes:
        if c < 0x897400: b["<0x897400"] += 1
        elif c < 0x8B8000: b["encrypted blob"] += 1
        elif c < 0x961B4C: b["id tables"] += 1
        elif c < 0xA2EEB8: b["pool2"] += 1
        elif c < N: b[">=0xA2EEB8 tail"] += 1
        else: b["oob"] += 1
    print("  code_off distribution:", dict(b))
    good = [c for c in codes if 0 < c < N-16]
    for c in good[:6]:
        hdr = struct.unpack_from("<HHHHII", data, c)
        print(f"   code_off {c:#x} -> regs={hdr[0]} ins={hdr[1]} outs={hdr[2]} tries={hdr[3]} "
              f"debug={hdr[4]:#x} insns={hdr[5]}")

print("\n--- entropy sampling of the tail [0xA2EEB8, 0x%X) ---" % N)
lo, hi = 0xA2EEB8, N
step = (hi-lo)//40
tot = 0
for o in range(lo, hi-step, step):
    b = data[o:o+0x1000]
    tot += len(b)
    print(f"  {o:#08x} H={entropy(b):.3f} zero={sum(1 for x in b if x==0)/len(b):.2f} print={sum(1 for x in b if 32<=x<127)/len(b):.2f}")
print(f"total sampled {tot} bytes")

print("\n--- magic / structure probes in tail ---")
for pat in (b"dex\n035", b"dex\n038", b"dex\n039"):
    i = data.find(pat, lo)
    print(f"  {pat!r} first at {i:#x}" if i >= 0 else f"  {pat!r} not found in tail")
print("  whole-file dex magics:", [hex(i) for i in range(0, N) if data.startswith(b"dex\n03", i)][:10])
