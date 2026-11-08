#!/usr/bin/env python3
#
# DEX2 MUTF-8 String Pool Walker
#
# Iterates sequential string_data_item entries and outputs JSON pool mapping.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Scans the unencrypted string data segment, decoding uleb128 length headers and null-terminated MUTF-8 byte sequences.
"""

"""Walk dex2 pool2 (plaintext) in app.dec.dex coordinates -> string list."""
import sys, json, struct
sys.path.insert(0, 'unpack')
from mutf8_walk import walk, mutf8_item

DEX = 'unpack/out/app.dec.dex'
d = open(DEX, 'rb').read()
POOL2 = 0x961B68
starts, end = walk(d, POOL2, len(d))
print(f"pool2 @0x{POOL2:X}: items={len(starts)} end=0x{end:X} span=0x{end-POOL2:X}")

out = []
for i, (off, nb) in enumerate(starts):
    # recompute length prefix
    o = off; ln = 0; sh = 0
    while True:
        b = d[o]; ln |= (b & 0x7f) << sh; o += 1
        if not b & 0x80: break
        sh += 7
    raw = d[o:o+nb]
    try:
        t = raw.decode('utf-8', 'replace')
    except Exception:
        t = raw.decode('latin1')
    out.append((i, off, ln, t))

json.dump([{'i': i, 'off': f'0x{off:X}', 'u16': ln, 's': t} for i, off, ln, t in out],
          open('unpack/out/pool2_walk.json', 'w', encoding='utf-8'), ensure_ascii=False)
print("saved unpack/out/pool2_walk.json")
for i in (1909, 1910, 1934, 1935):
    if i < len(out):
        print(f"  [{i}] off=0x{out[i][1]:X} u16={out[i][2]} {out[i][3]!r}")
print("first 5:", [(hex(o), t[:40]) for _, o, _, t in out[:5]])
print("last 3:", [(hex(o), t[:40]) for _, o, _, t in out[-3:]])
