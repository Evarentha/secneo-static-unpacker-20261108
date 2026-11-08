#!/usr/bin/env python3
#
# Sliding-Window Shannon Entropy Mapper
#
# Calculates entropy profiles to distinguish encrypted, compressed, and plaintext sections.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Generates entropy distribution data across file ranges to identify SM4-encrypted blocks (entropy ~7.998) versus compressed data.
"""

"""Block-entropy map of a file; prints contiguous runs of high/low entropy.

Usage: python entropy_map.py <file> [--start HEX] [--end HEX] [--bs N] [--thr F]
Entropy computed over byte histogram (8 bit) per block.
"""
import sys, math, argparse
from collections import Counter

def ent(b):
    n = len(b)
    if n == 0:
        return 0.0
    c = Counter(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path')
    ap.add_argument('--start', default='0')
    ap.add_argument('--end', default=None)
    ap.add_argument('--bs', type=int, default=4096)
    ap.add_argument('--thr', type=float, default=7.5)
    a = ap.parse_args()
    data = open(a.path, 'rb').read()
    s = int(a.start, 0)
    e = int(a.end, 0) if a.end else len(data)
    rows = []
    for off in range(s, e, a.bs):
        blk = data[off:min(off + a.bs, e)]
        rows.append((off, len(blk), ent(blk), sum(1 for x in blk if x == 0) / len(blk)))
    # compress into runs by high/low state
    runs = []
    for off, ln, h, zr in rows:
        state = 'HIGH' if h >= a.thr else 'LOW'
        if runs and runs[-1][0] == state:
            runs[-1][2] = off + ln
            runs[-1][3].append(h)
        else:
            runs.append([state, off, off + ln, [h]])
    print(f"# {a.path} size=0x{len(data):X} blocks={a.bs} thr={a.thr}")
    print(f"{'state':5} {'start':>12} {'end':>12} {'size':>10}  meanH  minH  maxH")
    for state, st, en, hs in runs:
        print(f"{state:5} 0x{st:010X} 0x{en:010X} 0x{en-st:08X}  {sum(hs)/len(hs):.4f} {min(hs):.4f} {max(hs):.4f}")

if __name__ == '__main__':
    main()
