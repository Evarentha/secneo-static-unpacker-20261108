#!/usr/bin/env python3
#
# EncryptUtil Class Signature Extractor
#
# Extracts Dalvik bytecode and method signatures for cryptography utility classes.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Parses Dalvik bytecode for com.target.app.EncryptUtil, extracting cryptographic routine signatures and constants.
"""

"""
手工解析 EncryptUtil 的 class_data_item + code_item + Dalvik 字节码。
绕过 androguard（map_list 被裁剪，它找不到 class_data/code 区段）。
"""
import struct
import sys

DEX = "app.dec.dex"
buf = open(DEX, "rb").read()
L = len(buf)

sids_size, sids_off = struct.unpack_from("<II", buf, 0x38)
tids_size, tids_off = struct.unpack_from("<II", buf, 0x40)
mids_size, mids_off = struct.unpack_from("<II", buf, 0x58)
cds_size, cds_off = struct.unpack_from("<II", buf, 0x60)


def uleb(b, o):
    r, s = 0, 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


def sleb(b, o):
    r, s = 0, 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                r -= (1 << s)
            return r, o


def get_str(idx):
    if idx >= sids_size:
        return None
    off = struct.unpack_from("<I", buf, sids_off + idx * 4)[0]
    if off >= L:
        return None
    _, o = uleb(buf, off)
    e = buf.find(b"\x00", o)
    if e < 0 or e - o > 500:
        return None
    try:
        return buf[o:e].decode("utf-8")
    except Exception:
        return None


def type_str(t):
    if t >= tids_size:
        return None
    s = struct.unpack_from("<I", buf, tids_off + t * 4)[0]
    return get_str(s)


def method_ref(midx):
    """method_id_item: class_idx(u2) proto_idx(u2) name_idx(u4)"""
    if midx >= mids_size:
        return None
    o = mids_off + midx * 8
    cls, proto, name = struct.unpack_from("<HHI", buf, o)
    return type_str(cls), get_str(name)


# ── 找 EncryptUtil 的 class_def ──
target_name = "Lcom/iflytek/edu/apm/base/network/EncryptUtil;"
cd_idx = None
for i in range(cds_size):
    base = cds_off + i * 32
    class_idx = struct.unpack_from("<I", buf, base)[0]
    if type_str(class_idx) == target_name:
        cd_idx = i
        cd_base = base
        break

if cd_idx is None:
    # 宽松：任何含 stu/EncryptUtil 的
    for i in range(cds_size):
        base = cds_off + i * 32
        t = type_str(struct.unpack_from("<I", buf, base)[0])
        if t and "network/EncryptUtil" in t:
            cd_idx, cd_base, target_name = i, base, t
            break

print(f"class_defs: {cds_size}")
if cd_idx is None:
    print("未找到 EncryptUtil class_def")
    sys.exit(1)

(class_idx, access, super_idx, if_off, src_idx, ann_off, cdoff, svoff) = \
    struct.unpack_from("<IIIIIIII", buf, cd_base)
print(f"\n★ class_def[{cd_idx}]  {target_name}")
print(f"  access=0x{access:x}  super={type_str(super_idx)}")
print(f"  annotations_off=0x{ann_off:x}  class_data_off=0x{cdoff:x}  static_values_off=0x{svoff:x}")

if not cdoff or cdoff >= L:
    print("class_data_off 无效"); sys.exit(1)

# ── 解析 class_data_item ──
o = cdoff
sf, o = uleb(buf, o)
inf, o = uleb(buf, o)
dm, o = uleb(buf, o)
vm, o = uleb(buf, o)
print(f"\n  static_fields={sf} instance_fields={inf} direct_methods={dm} virtual_methods={vm}")

methods = []


def read_fields(n, o):
    idx = 0
    for _ in range(n):
        d, o = uleb(buf, o)
        idx += d
        _, o = uleb(buf, o)   # access_flags
    return o


o = read_fields(sf, o)
o = read_fields(inf, o)


def read_methods(n, o):
    idx = 0
    for _ in range(n):
        d, o = uleb(buf, o)
        idx += d
        acc, o = uleb(buf, o)
        code_off, o = uleb(buf, o)
        methods.append((idx, acc, code_off))
    return o


o = read_methods(dm, o)
o = read_methods(vm, o)

print(f"\n=== 方法列表 ===")
for midx, acc, code_off in methods:
    ref = method_ref(midx)
    nm = ref[1] if ref else "?"
    print(f"  [{'static' if acc & 0x8 else '      '}] {nm:24s} code_off=0x{code_off:x}")

# ── 解析 code_item ──
def parse_code(off):
    if not off or off >= L:
        return None
    registers, ins, outs, tries_size, debug_off, insns_size = struct.unpack_from("<HHHHII", buf, off)
    insns_off = off + 16
    end = insns_off + insns_size * 2
    if end > L:
        return None
    insns = struct.unpack_from(f"<{insns_size}H", buf, insns_off)
    return dict(regs=registers, ins=ins, outs=outs, tries=tries_size,
                debug=debug_off, size=insns_size, insns=insns)


print(f"\n=== 各方法引用的字符串 ===")
for midx, acc, code_off in methods:
    ref = method_ref(midx)
    nm = ref[1] if ref else "?"
    ci = parse_code(code_off)
    if not ci:
        print(f"\n--- {nm}: 无代码")
        continue
    print(f"\n--- {nm}  (regs={ci['regs']} ins={ci['ins']} size={ci['size']}) ---")
    ins = ci["insns"]
    i = 0
    strs = []
    calls = []
    while i < len(ins):
        u = ins[i]
        op = u & 0xFF
        if op == 0x1A:      # const-string  vAA, string@BBBB
            if i + 1 < len(ins):
                s = get_str(ins[i + 1])
                if s:
                    strs.append(s)
            i += 2
            continue
        if op == 0x1B:      # const-string/jumbo vAA, string@BBBBBBBB
            if i + 2 < len(ins):
                sidx = ins[i + 1] | (ins[i + 2] << 16)
                s = get_str(sidx)
                if s:
                    strs.append(s)
            i += 3
            continue
        if op in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
            # invoke-kind  vC, vD, vE, vF, meth@BBBB
            mm = ins[i + 1] if i + 1 < len(ins) else 0
            r = method_ref(mm)
            if r:
                calls.append(f"{r[0]}.{r[1]}")
            i += 3
            continue
        if op in (0xFA, 0xFB):
            i += 4
            continue
        if op in (0xFC, 0xFD):
            i += 3
            continue
        if op in (0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
                  0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                  0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
                  0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
                  0x6A, 0x6B, 0x6C, 0x6D):
            i += 2
            continue
        if op in (0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C, 0xFD):
            i += 3
            continue
        if op == 0x18:      # const-wide
            i += 5
            continue
        if op == 0x17:      # const-wide/32
            i += 3
            continue
        if op in (0x13, 0x14, 0x15, 0x16, 0x19):
            i += 2
            continue
        if op in (0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23):
            i += 2
            continue
        i += 1
    for s in strs:
        print(f"    STR  {s[:120]}")
    for c in calls:
        if any(k in c for k in ("Cipher", "DES", "AES", "MessageDigest", "Base64", "String", "Util", "Encrypt")):
            print(f"    CALL {c}")
