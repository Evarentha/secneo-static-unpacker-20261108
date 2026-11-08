#!/usr/bin/env python3
#
# libDexHelper.so Static Native Unpacker
#
# Emulates libDexHelper.so self-extracting boot chain using Unicorn Engine.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Emulates ARM code execution from .init_proc through sub_AF76C and sub_AFBF0 to unpack the 439,185-byte decrypted native module.
"""

"""libDexHelper.so (梆梆 SecNeo) 二级脱壳 —— 纯静态, Unicorn 模拟内嵌解压器。

原理:
  容器 .so 的 .init_proc(0xaf184) -> sub_AFA84(0xafa84, mmap+memcpy)
     -> sub_AF76C(0xaf76c, 装载器) -> sub_AFBF0(0xafbf0, 自研 LZ 范围解码器)
  装载器结构在 vaddr 0xafe10:
     [3]=0x212e0 压缩源  [7]=0x6b391 解压后大小
     [8]=0x0     XOR 密钥(此处为 0)  [10]=0x3f0b8 压缩长度
用法: python unicorn_decompress_dexhelper.py libDexHelper.so out.bin
"""
import sys, struct
from unicorn import *
from unicorn.arm_const import *

SRC=0x212e0; SRCLEN=0x3f0b8; DSTLEN=0x6b391
SEGS=[(0x0,0x0,0x8c671),(0x8e460,0x8d460,0x8d14),(0xaf174,0x96174,0xcc8)]
FUNC=0xafbf0

def main(so, out):
    d=open(so,"rb").read()
    mu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    for va,off,sz in SEGS:
        base=va&~0xfff; size=((va+sz-base)+0xfff)&~0xfff
        mu.mem_map(base,size); mu.mem_write(va,d[off:off+sz])
    OUT=0x10000000; mu.mem_map(OUT,0x200000)
    LENP=0x12000000; mu.mem_map(LENP,0x1000)
    ST=0x30000000; mu.mem_map(ST,0x100000); mu.reg_write(UC_ARM_REG_SP,ST+0x80000)
    mu.reg_write(UC_ARM_REG_R0,SRC); mu.reg_write(UC_ARM_REG_R1,SRCLEN)
    mu.reg_write(UC_ARM_REG_R2,OUT); mu.reg_write(UC_ARM_REG_R3,LENP)
    mu.reg_write(UC_ARM_REG_LR,0xdeadbeef)
    try: mu.emu_start(FUNC,0xdeadbeef,count=50_000_000)
    except UcError as e: print("emu:",e)
    n=struct.unpack("<I",mu.mem_read(LENP,4))[0]
    print("decompressed size = 0x%x (%d)"%(n,n))
    data=bytes(mu.mem_read(OUT,n))
    open(out,"wb").write(data)
    print("wrote",out,len(data))
    print("ARM prologues:",data.count(b"\x2d\xe9"),"| OpenCommon@",data.find(b"OpenCommon"),
          "| Anonymous-DexFile@",data.find(b"Anonymous-DexFile"))
if __name__=="__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv)>2 else "dec.bin")
