#!/usr/bin/env python3
#
# DEX2 Table Boundary Discovery
#
# Computes relative and absolute offsets for all structural ID tables.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Scans memory offsets to establish definitive start and end boundaries for type_ids, proto_ids, field_ids, method_ids, and class_defs tables.
"""

# Step 2: sliding-window entropy to find the exact boundary of the high-entropy blob
# in [0x896000, 0x8B8000), then test both candidate string_ids starts.
import math, struct, collections

data = open("unpack/out/app.dec.dex", "rb").read()

def entropy(b):
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

print("--- sliding window entropy (1KB windows, step 1KB) over [0x894000,0x8B8000) ---")
lo, hi, W = 0x894000, 0x8B8000, 0x400
prev_state = None
for o in range(lo, hi, W):
    b = data[o:o+W]
    h = entropy(b); z = sum(1 for x in b if x == 0)/len(b)
    state = "HIGH" if h > 7.5 else ("low " if h < 6.0 else "mid ")
    if state != prev_state:
        print(f"  {o:#08x}  H={h:.3f} zero={z:.2f}  <-- transition to {state}")
        prev_state = state
print(f"  {hi:#08x}  (end)")

def try_string_ids(start, count, label):
    print(f"\n--- {label}: string_ids @ {start:#x}, count={count} ({count*4:#x}B) ---")
    end = start + count*4
    vals = struct.unpack_from("<%dI" % count, data, start)
    in_file = sum(1 for v in vals if 0 < v < len(data))
    # string_data_item = uleb128 utf16_len + MUTF8 bytes ; offset must point at a plausible one
    plausible = 0
    for v in vals[:4000]:
        if not (0 < v < len(data)-8):
            continue
        L = data[v]
        if L == 0 or L > 0x7f:      # short strings dominate; 0 = empty string (legal but rare)
            continue
        if v + 1 + L <= len(data):
            seg = data[v+1:v+1+L]
            if all(0x20 <= c < 0x7f for c in seg) or all(c >= 0x0a for c in seg):
                plausible += 1
    monot = sum(1 for i in range(1, min(count, 4000)) if vals[i] > vals[i-1])
    b = data[start:end]
    print(f"  entropy={entropy(b):.4f} zero={sum(1 for x in b if x==0)/len(b):.3f}")
    print(f"  in-file offsets {in_file}/{count} ({in_file/count:.4f})")
    print(f"  increasing steps in first 4000: {monot}/3999")
    print(f"  plausible string_data_item at offset (first 4000): {plausible}/4000")
    print(f"  first 8: {vals[:8]}")

# H1: no insert  -> start = type_ids - 32388*4
try_string_ids(0x8B8000 - 32388*4, 32388, "H1 no-insert")
# H2: with dex1-style 0x1000 insert after header
try_string_ids(0x896F80 + 0x70 + 0x1000, (0x8B8000 - (0x896F80+0x70+0x1000))//4, "H2 insert-0x1000")

print("\n--- what is at 0x896F80..0x898600 (first 0x60 bytes of each 0x100 chunk) ---")
for o in range(0x896F80, 0x898600, 0x100):
    print(f"  {o:#08x} " + data[o:o+0x20].hex(" "))
