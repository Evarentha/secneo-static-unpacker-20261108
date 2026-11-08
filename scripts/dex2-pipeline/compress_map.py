#!/usr/bin/env python3
#
# Container Compression Pattern Analyzer
#
# Maps compressed segment boundaries and compression ratios across payloads.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Analyzes block compression profiles within the SecNeo container.
"""

"""Compressibility + entropy run map (robust for small blocks).

A block of random/encrypted bytes compresses to ~1.005x; structured dex code
compresses to < 0.9x. Use zlib level 6 length ratio as the discriminator.
"""
import sys, zlib, math, argparse
from collections import Counter

def ent(b):
    n = len(b); c = Counter(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path'); ap.add_argument('--start', default='0')
    ap.add_argument('--end', default=None); ap.add_argument('--bs', type=int, default=4096)
    ap.add_argument('--ratio', type=float, default=0.99)
    a = ap.parse_args()
    data = open(a.path, 'rb').read()
    s = int(a.start, 0); e = int(a.end, 0) if a.end else len(data)
    runs = []
    for off in range(s, e, a.bs):
        blk = data[off:min(off+a.bs, e)]
        r = len(zlib.compress(blk, 6))/len(blk)
        h = ent(blk)
        state = 'RAND' if r >= a.ratio else 'STRC'
        if runs and runs[-1][0] == state:
            runs[-1][2] = off+len(blk); runs[-1][3].append(r); runs[-1][4].append(h)
        else:
            runs.append([state, off, off+len(blk), [r], [h]])
    print(f"# {a.path} size=0x{len(data):X} bs={a.bs} ratio>={a.ratio} => RAND")
    print(f"{'state':5} {'start':>12} {'end':>12} {'size':>10}  meanR  minR  maxR  meanH")
    for state, st, en, rs, hs in runs:
        print(f"{state:5} 0x{st:010X} 0x{en:010X} 0x{en-st:08X}  {sum(rs)/len(rs):.4f} {min(rs):.4f} {max(rs):.4f} {sum(hs)/len(hs):.4f}")

if __name__ == '__main__':
    main()
