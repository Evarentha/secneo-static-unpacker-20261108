#!/usr/bin/env python3
#
# SecNeo Container Payload DEX Rebuilder
#
# Extracts and reconstructs Dalvik executable files from SecNeo container payloads.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Carves the primary application payload from raw SecNeo classes.dex files and writes an aligned, structurally valid DEX image.
"""

"""dex_rebuild.py — 梆梆 SecNeo "string_ids-only" 加固的静态 dex 重建。

原理: SecNeo 只加密 string_ids 表, 其余 id 表/class_def/code_item 明文。
      真实 dex 头部被移除; 通过自引用 map_list 反解 base 与各段表, 重建标准头。
用法: python dex_rebuild.py <protected_classes.dex> [out.dex]
说明: 产物结构有效(类/方法/字段齐全), 字符串需另解 string_ids 密文后替换。
"""
import sys, struct, hashlib, zlib

# 该样本实测的段表 (relative to base); 换样本时由自引用 map 项重新求解 base
MAP = [("string_id",0x70,62762),("type_id",0x3d518,9354),("proto_id",0x46740,14517),
       ("field_id",0x70fbc,64469),("method_id",0xeee64,62406),("class_def",0x168c94,7578),
       ("debug_info",0x1a3fd4,62762),("type_list",0x3387d8,8183),("annotations_directory",0x34ce4a,1018),
       ("encoded_array",0x35b32a,10322),("class_data",0x38fbf8,9987),("annotation_set",0x3a8e5c,266),
       ("hiddenapi",0x3aa2fc,5976),("annotation",0x3e89ec,41823),("string_data",0x43f2c4,51259),
       ("code_item",0x813ee8,7336),("map_list",0x89716c,1)]
MAP_OFF = 0x89716c
MAP_ENTRIES = 18
# base 求解: 找自引用 map 项的 offset 字段 -> base = map_count_abs - MAP_OFF
def solve_base(b):
    pat_self = struct.pack("<HHI", 0x1000, 0, 1)          # map_list entry header
    idx = 0
    while True:
        j = b.find(pat_self, idx)
        if j < 0: return None
        off = struct.unpack_from("<I", b, j+8)[0]
        if off == MAP_OFF:
            # map entries end at j+12; count field is 4 + 18*12 before j
            first = j - (MAP_ENTRIES-1)*12
            cnt = struct.unpack_from("<I", b, first-4)[0]
            if cnt == MAP_ENTRIES:
                return first - 4 - MAP_OFF
        idx = j+1

def sec(name):
    for n,o,s in MAP:
        if n == name: return o, s
    raise KeyError(name)

def rebuild(src, out):
    b = open(src, "rb").read()
    B = solve_base(b)
    if B is None: raise SystemExit("map_list not found")
    size = MAP_OFF + 4 + MAP_ENTRIES*12
    data_off, _ = sec("string_data")
    # data_off should be first data section = class_def end; use debug_info per sample
    data_off = sec("debug_info")[0]
    h = bytearray(0x70)
    h[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", h, 0x20, size)
    struct.pack_into("<I", h, 0x24, 0x70)
    struct.pack_into("<I", h, 0x28, 0x12345678)
    struct.pack_into("<I", h, 0x34, MAP_OFF)
    struct.pack_into("<II", h, 0x38, sec("string_id")[1], sec("string_id")[0])
    struct.pack_into("<II", h, 0x40, sec("type_id")[1],   sec("type_id")[0])
    struct.pack_into("<II", h, 0x48, sec("proto_id")[1],  sec("proto_id")[0])
    struct.pack_into("<II", h, 0x50, sec("field_id")[1],  sec("field_id")[0])
    struct.pack_into("<II", h, 0x58, sec("method_id")[1], sec("method_id")[0])
    struct.pack_into("<II", h, 0x60, sec("class_def")[1], sec("class_def")[0])
    struct.pack_into("<II", h, 0x68, size-data_off, data_off)
    body = bytearray(b[B:B+size])
    if len(body) != size: raise SystemExit("carve short: %d != %d"%(len(body),size))
    body[0:0x70] = h
    body[0x08:0x0C] = b"\x00"*4
    body[0x0C:0x20] = hashlib.sha1(bytes(body[0x20:])).digest()
    struct.pack_into("<I", body, 0x08, zlib.adler32(bytes(body[0x0C:])) & 0xffffffff)
    open(out, "wb").write(body)
    print("base=0x%x size=0x%x -> %s" % (B, size, out))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    rebuild(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "rebuilt.dex")
