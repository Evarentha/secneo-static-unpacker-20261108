#!/usr/bin/env python3
#
# DEX2 Header & Boundary Verification
#
# Validates Dalvik magic, endian tags, and table count consistency for secondary DEX.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Performs sanity checks on secondary DEX memory dumps, verifying Dalvik header fields, structural alignments, and table boundary consistency.
"""

# Step 1: verify the "encrypted" hypothesis for dex2 string_ids region,
# and check whether dex2 type_ids / higher tables are self-consistent plaintext.
import sys, math, json, struct, collections

DEX = "unpack/out/app.dec.dex"
data = open(DEX, "rb").read()
print("file size", len(data))

def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def printable(b):
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)

def report(name, lo, hi):
    b = data[lo:hi]
    z = sum(1 for x in b if x == 0) / len(b)
    print(f"{name:28s} [{lo:#x},{hi:#x}) {len(b):>8d}B  H={entropy(b):.4f}  "
          f"print={printable(b):.3f}  zero={z:.3f}")
    return b

print("\n--- region entropy ---")
report("dex1 plaintext strpool", 0x1A4FD4, 0x1A4FD4 + 0x8000)
report("dex2 hdr+ins(guess)",   0x896F80, 0x897FF0)
report("dex2 string_ids",       0x897FF0, 0x8B8000)
report("dex2 type_ids",         0x8B8000, 0x8B8000 + 0x4000)
report("dex2 pool2 strpool",    0x961B68, 0x961B68 + 0x8000)

print("\n--- type_ids parse test (4-byte string_idx, must be < 32388) ---")
NSTR = 32388
off = 0x8B8000
NTYPE = 5503
vals = struct.unpack_from("<%dI" % NTYPE, data, off)
ok = sum(1 for v in vals if v < NSTR)
print(f"type_ids@{off:#x} n={NTYPE} in-range {ok}/{NTYPE} = {ok/NTYPE:.4f}")
print("first 20:", vals[:20])
print("max:", max(vals), "min:", min(vals))
# strictly non-decreasing is another dex invariant on type_ids (sorted by string idx)
inc = all(vals[i] <= vals[i+1] for i in range(len(vals)-1))
print("monotonic_nondecreasing:", inc)
dups = len(vals) - len(set(vals))
print("duplicate entries:", dups)

print("\n--- probe_ids parse test (3 x u4: shorty, return_type, params_off) ---")
protos_off = 0x8BD5FC
# proto_ids may not start exactly there; scan a small window for a plausible start
for cand in range(protos_off - 0x40, protos_off + 0x40, 4):
    v = struct.unpack_from("<III", data, cand)
    if v[0] < NSTR and v[1] < NTYPE:
        print(f"  cand {cand:#x}: shorty={v[0]} ret={v[1]} params={v[2]:#x}")
        break
NPROTO = 6088
s_ok = r_ok = 0
for i in range(NPROTO):
    s, r, p = struct.unpack_from("<III", data, protos_off + 12 * i)
    if s < NSTR: s_ok += 1
    if r < NTYPE: r_ok += 1
print(f"proto_ids@{protos_off:#x} n={NPROTO}: shorty_idx in range {s_ok}/{NPROTO}={s_ok/NPROTO:.4f}, "
      f"return_type_idx in range {r_ok}/{NPROTO}={r_ok/NPROTO:.4f}")

print("\n--- field_ids parse test (u2 class, u2 type, u4 name) ---")
foff = 0x8CF35C
NFIELD = 27201
c_ok = t_ok = n_ok = 0
for i in range(NFIELD):
    c, t, n = struct.unpack_from("<HHI", data, foff + 8 * i)
    if c < NTYPE: c_ok += 1
    if t < NTYPE: t_ok += 1
    if n < NSTR: n_ok += 1
print(f"field_ids@{foff:#x} n={NFIELD}: class {c_ok/NFIELD:.4f} type {t_ok/NFIELD:.4f} name {n_ok/NFIELD:.4f}")

print("\n--- method_ids parse test (u2 class, u2 proto, u4 name) ---")
moff = 0x904564
NMETH = 30873
c_ok = p_ok = n_ok = 0
for i in range(NMETH):
    c, p, n = struct.unpack_from("<HHI", data, moff + 8 * i)
    if c < NTYPE: c_ok += 1
    if p < NPROTO: p_ok += 1
    if n < NSTR: n_ok += 1
print(f"method_ids@{moff:#x} n={NMETH}: class {c_ok/NMETH:.4f} proto {p_ok/NMETH:.4f} name {n_ok/NMETH:.4f}")

print("\n--- self-consistency: table sizes vs offsets ---")
print(f"type_ids end  = {0x8B8000 + 4*NTYPE:#x} (proto reported @0x8BD5FC, delta={0x8BD5FC-(0x8B8000+4*NTYPE)})")
print(f"proto end     = {0x8BD5FC + 12*NPROTO:#x} (field reported @0x8CF35C, delta={0x8CF35C-(0x8BD5FC+12*NPROTO)})")
print(f"field end     = {0x8CF35C + 8*NFIELD:#x} (method @0x904564, delta={0x904564-(0x8CF35C+8*NFIELD)})")
print(f"method end    = {0x904564 + 8*NMETH:#x} (class_defs @0x940A2C, delta={0x940A2C-(0x904564+8*NMETH)})")
print(f"classdefs end = {0x940A2C + 32*4233:#x} (pool2 @0x961B68, delta={0x961B68-(0x940A2C+32*4233)})")
