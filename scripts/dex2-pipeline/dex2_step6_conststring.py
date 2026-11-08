#!/usr/bin/env python3
#
# Dalvik const-string Opcode Scanner
#
# Scans method bytecode for const-string instructions to build plaintext anchors.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Disassembles method code_item streams to locate const-string and const-string/jumbo opcodes, recording string index cross-references.
"""

# Step 6: hunt `const-string` / `const-string/jumbo` in dex2's plaintext data tail,
# looking for the pool2 /mdm indices. Chunked <=256KB scans, hard bounds.
import struct, sys, json

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
NSTR = 32388
urls = json.load(open("unpack/out/pool2_mdm_urls.json"))
want = {i for i, _ in urls["urls"]} | {i for i, _ in urls["neighborhood_MDMLogin_MDMUrls"]}
want_map = {i: s for i, s in urls["urls"]}
want_map.update({i: s for i, s in urls["neighborhood_MDMLogin_MDMUrls"]})

LO, HI = 0xA2EEB8, N
CHUNK = 0x40000  # 256 KB
print(f"scanning [{LO:#x}, {HI:#x}) = {HI-LO} bytes in {CHUNK:#x} chunks, step 2")

hits = []          # (pos, width, str_idx)
count_cs = 0       # total const-string candidates whose index < NSTR
for base in range(LO, HI, CHUNK):
    end = min(base + CHUNK, HI)
    buf = data[base:end]
    n = len(buf) - 6
    off = 0
    while off < n:
        w = buf[off] | (buf[off+1] << 8)
        if (w & 0xff) == 0x1a:                                  # const-string 21c
            idx = buf[off+2] | (buf[off+3] << 8)
            if idx < NSTR:
                count_cs += 1
                if idx in want: hits.append((base+off, 2, idx))
        elif (w & 0xff) == 0x1b:                                # const-string/jumbo 31c
            idx = buf[off+2] | (buf[off+3] << 8) | (buf[off+4] << 16) | (buf[off+5] << 24)
            if idx < NSTR:
                count_cs += 1
                if idx in want: hits.append((base+off, 3, idx))
        off += 2
    print(f"  chunk {base:#08x}-{end:#08x} done, running hits={len(hits)}")

print(f"\ntotal in-range const-string candidates in tail: {count_cs}")
print(f"hits on /mdm or MDM* strings: {len(hits)}")
for pos, wid, idx in hits[:60]:
    print(f"  {pos:#08x} width={wid} str_idx={idx} -> {want_map[idx]}")
    print("    ctx: " + data[max(0,pos-24):pos+24].hex(" "))

# fallback: any const-string at all pointing at the /mdm block
if not hits:
    print("\nno direct hits; dumping nearest const-string index histogram around the /mdm block")
    from collections import Counter
    c = Counter()
    for base in range(LO, HI, CHUNK):
        end = min(base + CHUNK, HI)
        buf = data[base:end]
        for off in range(0, len(buf)-4, 2):
            w = buf[off] | (buf[off+1] << 8)
            if (w & 0xff) == 0x1a:
                idx = buf[off+2] | (buf[off+3] << 8)
                if 1880 <= idx <= 2000: c[idx] += 1
    print("  indices in [1880,2000]:", dict(sorted(c.items())[:40]))
