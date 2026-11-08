#!/usr/bin/env python3
#
# Heuristic Dalvik code_item Scanner
#
# Scans memory buffers for valid code_item structures using heuristic structural matching.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Identifies potential method bodies in unstructured memory dumps by matching Dalvik code_item header signatures and instruction boundaries.
"""

"""Locate code_items in app.dec.dex by full dalvik insn-stream validation."""
import struct, sys, json

DEX = 'unpack/out/app.dec.dex'
d = open(DEX, 'rb').read()
L = len(d)

# dalvik 035 instruction width in 16-bit code units (index 0..0xff)
W = [1] * 0x100
for op, w in [
    (0x02, 2), (0x03, 3), (0x05, 2), (0x06, 3), (0x08, 2), (0x09, 3),
    (0x0b, 2), (0x0c, 3), (0x0e, 1), (0x0f, 1), (0x10, 1), (0x11, 1),
    (0x13, 2), (0x14, 3), (0x15, 2), (0x16, 2), (0x17, 3), (0x18, 2), (0x19, 3),
    (0x1a, 2), (0x1b, 3), (0x1c, 2), (0x1f, 2), (0x20, 2), (0x22, 2), (0x23, 2),
    (0x24, 3), (0x25, 3), (0x26, 3), (0x29, 2), (0x2a, 3), (0x2b, 3), (0x2c, 3),
]:
    W[op] = w
for op in range(0x2d, 0x32): W[op] = 2
for op in range(0x32, 0x3e): W[op] = 2
for op in range(0x44, 0x6e): W[op] = 2
for op in range(0x6e, 0x73): W[op] = 3
for op in range(0x74, 0x79): W[op] = 3
for op in range(0x90, 0xb0): W[op] = 2
for op in range(0xd0, 0xe3): W[op] = 2
INVALID = set(range(0x3e, 0x44)) | {0x73, 0x79, 0x7a, 0xe3} | set(range(0xe4, 0x100))
INVALID -= set()

def insns_ok(off, n_units):
    """Validate a full insn stream; returns (#const-string idxs, #insns) or None."""
    p = off; end = off + n_units * 2
    if end > L: return None
    cs = []
    n = 0
    while p < end:
        op = d[p]
        if op in INVALID:
            if op == 0x00:              # payloads (nop with high byte tag)
                tag = d[p + 1]
                if tag == 0x01:         # packed-switch-payload
                    if p + 4 > end: return None
                    size = struct.unpack_from('<H', d, p + 2)[0]
                    p += (size * 2 + 4) * 2
                elif tag == 0x02:       # sparse-switch-payload
                    if p + 4 > end: return None
                    size = struct.unpack_from('<H', d, p + 2)[0]
                    p += (size * 4 + 2) * 2
                elif tag == 0x03:       # fill-array-data-payload
                    if p + 8 > end: return None
                    width = struct.unpack_from('<H', d, p + 2)[0]
                    size = struct.unpack_from('<I', d, p + 4)[0]
                    p += 4 + ((width * size + 1) // 2) * 2
                else:
                    return None
                n += 1
                continue
            return None
        w = W[op]
        if op == 0x1a:
            cs.append(struct.unpack_from('<H', d, p + 2)[0])
        elif op == 0x1b:
            cs.append(struct.unpack_from('<I', d, p + 2)[0])
        p += w * 2
        n += 1
    if p != end: return None
    return cs, n

def try_item(o):
    if o + 16 > L: return None
    reg, ins, outs, tries, dbg, nsz = struct.unpack_from('<HHHHII', d, o)
    if not (0 < reg <= 255): return None
    if ins > reg: return None
    if outs > 15: return None
    if tries > 200: return None
    if not (0 < nsz < 200000): return None
    r = insns_ok(o + 16, nsz)
    if r is None: return None
    return (reg, ins, outs, tries, dbg, nsz, r[0], r[1])

if __name__ == '__main__':
    s = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0
    e = int(sys.argv[2], 0) if len(sys.argv) > 2 else L
    out = []
    o = s & ~3
    while o < e:
        r = try_item(o)
        if r:
            out.append((o, r))
        o += 4
    print(f"code_items found in [0x{s:X},0x{e:X}): {len(out)}")
    for o, r in out[:30]:
        print(f"  0x{o:08X} reg={r[0]} ins={r[1]} outs={r[2]} tries={r[3]} dbg=0x{r[4]:X} n={r[5]} ncs={len(r[6])}")
    json.dump([[o, list(r[:6]), r[6]] for o, r in out], open('unpack/out/code_items_scan.json', 'w'))
    print("saved unpack/out/code_items_scan.json")
