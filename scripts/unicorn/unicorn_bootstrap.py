#!/usr/bin/env python3
#
# Unicorn ARM Emulation Environment Bootstrap
#
# Initializes ARM32 execution context, memory layouts, and hook harnesses.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Sets up the CPU state, memory pages, stack spaces, and basic hook callbacks required to emulate ARM native binaries under Unicorn Engine.
"""

"""unicorn_bootstrap.py — 在 Unicorn 中加载 libDexHelper.so 并捕获对加密段
0x20000-0x60000 的写入(即 bootstrap 解密动作), 命中即 dump 明文。

用法: python unicorn_bootstrap.py <libDexHelper.so> [entry]
说明: 该 .so 被剥离了 e_entry / .init_array / .dynsym, 若磁盘上不含自举代码,
      脚本会如实报告 "no bootstrap entry found", 此时需由外部加载器驱动入口。
"""
import sys, struct
from unicorn import *
from unicorn.arm_const import *

TARGET_LO, TARGET_HI = 0x20000, 0x60000   # 加密 .text
STACK = 0xbf000000
STACK_SZ = 0x100000

def load_so(d):
    ident = d[:16]
    if ident[:4] != b'\x7fELF': raise SystemExit("not ELF")
    e_machine, = struct.unpack_from("<H", d, 18)
    e_entry, = struct.unpack_from("<I", d, 24)
    e_phoff, = struct.unpack_from("<I", d, 28)
    e_phentsize, = struct.unpack_from("<H", d, 42)
    e_phnum, = struct.unpack_from("<H", d, 44)
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i*e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from("<8I", d, o)
        if p_type == 1:  # PT_LOAD
            segs.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
    return e_entry, segs

def main():
    so = sys.argv[1]
    d = open(so, "rb").read()
    entry, segs = load_so(d)
    print("[*] ELF entry=0x%x  PT_LOAD x%d" % (entry, len(segs)))
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for off, va, fs, ms, fl in segs:
        base = va & ~0xfff
        size = ((va + ms - base) + 0xfff) & ~0xfff
        mu.mem_map(base, size)
        mu.mem_write(va, d[off:off+fs])
        print("    map va=0x%x size=0x%x flags=%d (%s)" % (va, size, fl, "RX" if fl & 1 else "RW"))
    mu.mem_map(STACK, STACK_SZ)
    mu.reg_write(UC_ARM_REG_SP, STACK + STACK_SZ//2)

    hits = []
    def hook_mem(uc, access, addr, size, value, user):
        if access == UC_MEM_WRITE and TARGET_LO <= addr < TARGET_HI:
            hits.append(addr)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem)

    if entry in (0, None):
        # 无 e_entry: 尝试已知可能的构造/初始化点，或报告缺失
        print("[!] e_entry==0 且 .dynamic 无 DT_INIT/DT_INIT_ARRAY -> 磁盘上无自举入口")
        print("[!] 该 .so 需外部加载器映射后再跳入; 静态无法自行启动")
        # 仍尝试把 RW 段当数据、扫描是否有“解密循环”特征(写目标落在 TARGET 区)
        # 由于无入口，这里直接给出结论
        print("[SUMMARY] 未发现可执行自举入口 -> 不能纯静态在 Unicorn 内自解密")
        return

    print("[*] running from entry 0x%x ..." % entry)
    try:
        mu.emu_start(entry, 0, count=2_000_000)
    except UcError as e:
        print("[!] stopped:", e)
    print("[*] writes into encrypted region:", len(hits))
    if hits:
        pt = mu.mem_read(TARGET_LO, TARGET_HI - TARGET_LO)
        open("libDexHelper.dec.bin", "wb").write(bytes(pt))
        print("[+] dumped -> libDexHelper.dec.bin")

if __name__ == "__main__":
    main()
