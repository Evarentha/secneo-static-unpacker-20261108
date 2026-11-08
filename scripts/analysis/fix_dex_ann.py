#!/usr/bin/env python3
#
# DEX Annotation Directory Sanitizer
#
# Zeros out out-of-bounds annotations_off pointers caused by packer truncation.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Fixes invalid annotation offset references in reconstructed DEX files to allow standard decompilers to process class definitions cleanly.
"""

"""
DEX 修复：把越界的 annotations_off 清零，让 jadx/androguard 能解析。

DEX 结构（class_def_item，32 字节）：
  +0x00 u4 class_idx
  +0x04 u4 access_flags
  +0x08 u4 superclass_idx
  +0x0C u4 interfaces_off
  +0x10 u4 source_file_idx
  +0x14 u4 annotations_off      ← 越界的就是这个
  +0x18 u4 class_data_off
  +0x1C u4 static_values_off
"""
import struct
import sys

SRC = "app.dec.dex"
DST = "app.dec.FIXED.dex"

buf = bytearray(open(SRC, "rb").read())
print(f"读取 {SRC}: {len(buf)}B  magic={bytes(buf[:8])}")

file_size = struct.unpack_from("<I", buf, 0x20)[0]
sids_size, sids_off = struct.unpack_from("<II", buf, 0x38)
tids_size, tids_off = struct.unpack_from("<II", buf, 0x40)
cds_size, cds_off = struct.unpack_from("<II", buf, 0x60)

print(f"  file_size(header)={file_size}  实际={len(buf)}")
print(f"  string_ids: {sids_size} @0x{sids_off:x}")
print(f"  type_ids:   {tids_size} @0x{tids_off:x}")
print(f"  class_defs: {cds_size} @0x{cds_off:x}")


def uleb(b, o):
    r = 0
    s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


def get_str(idx):
    if idx >= sids_size:
        return None
    off = struct.unpack_from("<I", buf, sids_off + idx * 4)[0]
    if off >= len(buf):
        return None
    _, o = uleb(buf, off)
    e = buf.find(b"\x00", o)
    if e < 0 or e - o > 400:
        return None
    try:
        return bytes(buf[o:e]).decode("utf-8")
    except Exception:
        return None


def get_type_str(tidx):
    if tidx >= tids_size:
        return None
    sidx = struct.unpack_from("<I", buf, tids_off + tidx * 4)[0]
    return get_str(sidx)


# 扫描所有 class_def，找出越界字段
LIMIT = len(buf)
fixed_ann = 0
fixed_cd = 0
fixed_sv = 0
targets = []
corrupt = 0

print("\n扫描 class_defs ...")
for i in range(cds_size):
    base = cds_off + i * 32
    if base + 32 > LIMIT:
        break
    class_idx, access, super_idx, if_off, src_idx, ann_off, cd_off, sv_off = \
        struct.unpack_from("<IIIIIIII", buf, base)
    bad = False
    if ann_off and ann_off >= LIMIT:
        fixed_ann += 1
        bad = True
        struct.pack_into("<I", buf, base + 0x14, 0)
    if cd_off and cd_off >= LIMIT:
        fixed_cd += 1
        bad = True
        struct.pack_into("<I", buf, base + 0x18, 0)
    if sv_off and sv_off >= LIMIT:
        fixed_sv += 1
        bad = True
        struct.pack_into("<I", buf, base + 0x1C, 0)
    if if_off and if_off >= LIMIT:
        bad = True
        struct.pack_into("<I", buf, base + 0x0C, 0)
    if bad:
        corrupt += 1
        t = get_type_str(class_idx)
        if t and "EncryptUtil" in (t or ""):
            targets.append((i, t, ann_off, cd_off, sv_off))

print(f"  损坏 class_def: {corrupt}/{cds_size}")
print(f"  清零 annotations_off: {fixed_ann}")
print(f"  清零 class_data_off:  {fixed_cd}")
print(f"  清零 static_values_off:{fixed_sv}")
if targets:
    print("\n★ EncryptUtil 相关:")
    for i, t, a, c, s in targets:
        print(f"  class_def[{i}] {t}  ann=0x{a:x} cd=0x{c:x} sv=0x{s:x}")

# 同时修 header 里的 file_size / data_size 偏差（如果有）
if file_size != len(buf):
    struct.pack_into("<I", buf, 0x20, len(buf))
    print(f"\n修正 header file_size: {file_size} → {len(buf)}")

open(DST, "wb").write(buf)
print(f"\n已写出 {DST}  ({len(buf)}B)")

# 验证
import hashlib
print(f"  sha256(src) = {hashlib.sha256(open(SRC,'rb').read()).hexdigest()[:32]}")
print(f"  sha256(dst) = {hashlib.sha256(bytes(buf)).hexdigest()[:32]}")
