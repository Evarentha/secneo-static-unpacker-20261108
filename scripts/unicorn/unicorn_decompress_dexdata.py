#!/usr/bin/env python3
#
# SecNeo Container LZ Stream Emulated Decompressor
#
# Decompresses dexdata0 payload streams using the native LZ algorithm via emulation.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Executes the native decompression routine from libDexHelper.so inside a lightweight Unicorn ARM context to decompress arbitrary dexdata0 streams.
"""

"""用 libDexHelper.so 的 sub_AFBF0 解压 classes.dex 的 dexdata0 载荷"""
import sys, zipfile, struct
from unicorn import *
from unicorn.arm_const import *

SO   = sys.argv[1] if len(sys.argv)>1 else r"E:/Team/Project/日志/apk/6.0-1/管控平台_v5.6.10.4.xkt.apk::lib/armeabi-v7a/libDexHelper.so"
APK  = r"E:/Team/Project/日志/apk/6.0-1/管控平台_v5.6.10.4.xkt.apk"
OUTB = sys.argv[2] if len(sys.argv)>2 else "unpack/out/dexdata0.dec.bin"
SRC_OFF = int(sys.argv[3],0) if len(sys.argv)>3 else 0x4460   # 载荷起点
FUNC=0xafbf0
SEGS=[(0x0,0x0,0x8c671),(0x8e460,0x8d460,0x8d14),(0xaf174,0x96174,0xcc8)]

z=zipfile.ZipFile(APK)
so=z.read("lib/armeabi-v7a/libDexHelper.so")
dex=z.read("classes.dex")
payload=dex[SRC_OFF:]
print("so",len(so),"dex",len(dex),"payload @%#x len %d"%(SRC_OFF,len(payload)))

mu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
for va,off,sz in SEGS:
    base=va&~0xfff; size=((va+sz-base)+0xfff)&~0xfff
    mu.mem_map(base,size); mu.mem_write(va,so[off:off+sz])
IN=0x08000000; mu.mem_map(IN, (len(payload)+0xfff)&~0xfff)
mu.mem_write(IN,payload)
OUT=0x10000000; mu.mem_map(OUT,0x2000000)
LENP=0x12000000; mu.mem_map(LENP,0x1000)
ST=0x30000000; mu.mem_map(ST,0x100000); mu.reg_write(UC_ARM_REG_SP,ST+0x80000)
mu.reg_write(UC_ARM_REG_R0,IN)
mu.reg_write(UC_ARM_REG_R1,len(payload)&0xffffffff)
mu.reg_write(UC_ARM_REG_R2,OUT)
mu.reg_write(UC_ARM_REG_R3,LENP)
mu.reg_write(UC_ARM_REG_LR,0xdeadbeef)
try: mu.emu_start(FUNC,0xdeadbeef,count=200_000_000)
except UcError as e: print("emu:",e)
n=struct.unpack("<I",mu.mem_read(LENP,4))[0]
print("outlen = 0x%x (%d)"%(n,n))
if 0<n<0x2000000:
    data=bytes(mu.mem_read(OUT,n))
    open(OUTB,"wb").write(data)
    print("wrote",OUTB,len(data),"magic",data[:8],"dex?",data[:4]==b'dex\n')
else:
    print("bad length")
