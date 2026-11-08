#!/usr/bin/env python3
#
# String Index Reference Cross-Mapper
#
# Cross-references decoded string pool literals against method invocation sites.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Builds mapping correlations between plaintext string pool items and decompiled instruction operands.
"""

# Step 10: rebuild dex2's string index map correctly.
# pool2 (file order) is NOT identical to index order (13 inversions) -> index order = dex sort order.
# Index ordering key = UTF-16 code unit sequence (that is what dex string_ids is sorted by).
import struct, io, json

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
pool = json.load(io.open("unpack/out/pool2_walk.json", encoding="utf-8"))

def u16key(s):
    b = s.encode("utf-16-le", "surrogatepass")
    n = len(b)//2
    return struct.unpack("<%dH" % n, b) if n else ()

items = [(x["s"], x["off"]) for x in pool]
items.sort(key=lambda t: u16key(t[0]))
S = [s for s, _ in items]
ORDERED_OFF = [int(o, 16) for _, o in items]
json.dump(S, open("unpack/out/dex2_strings_by_index.json", "w", encoding="utf-8"), ensure_ascii=False)

NTYPE, NPROTO, NFIELD, NMETH = 5503, 6088, 27201, 30873
T_TYPE, T_PROTO, T_FIELD, T_METH = 0x8B8000, 0x8BD5FC, 0x8CF35C, 0x904564
def s_of(i): return S[i] if 0 <= i < len(S) else f"<str{i}>"
tn = lambda t: s_of(struct.unpack_from("<I", data, T_TYPE+4*t)[0]) if t < NTYPE else f"<t{t}>"

print("sanity checks on the rebuilt map")
for probe in ("<init>", "<clinit>", "/mdm/loginInitV3", "toString", "onCreate", "MDMLogin", "MDMUrls"):
    print(f"   {probe!r:22s} -> index {S.index(probe) if probe in S else 'ABSENT'}")

import collections
names = collections.Counter(s_of(struct.unpack_from("<HHI", data, T_METH+8*m)[2]) for m in range(NMETH))
print("\ntop method names:", names.most_common(8))
print("methods named <init>:", names["<init>"], " <clinit>:", names["<clinit>"])

CLASS_OFF = 0x940A2C
java = tot = 0
src = collections.Counter()
for i in range(4233):
    _, _, _, _, sfi, _, _, _ = struct.unpack_from("<8I", data, CLASS_OFF+32*i)
    if sfi and sfi != 0xFFFFFFFF:
        tot += 1
        v = s_of(sfi); src[v] += 1
        if v.endswith(".java") or v.endswith(".kt"): java += 1
print(f"source_file_idx -> .java/.kt : {java}/{tot}")
print("top source files:", src.most_common(10))
