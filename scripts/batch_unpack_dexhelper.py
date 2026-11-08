#!/usr/bin/env python3
#
# Batch libDexHelper.so Unpacker
#
# Scans directories and unpacks libDexHelper.so native payloads using Unicorn emulation.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Iterates over directories containing unpacked APK native libraries, identifies libDexHelper.so instances, and invokes the Unicorn unpacker.
"""

import glob,os,struct,hashlib
from unicorn import *
from unicorn.arm_const import *
SEGS=[(0x0,0x0,0x8c671),(0x8e460,0x8d460,0x8d14),(0xaf174,0x96174,0xcc8)]
SRC=0x212e0; SRCLEN=0x3f0b8; FUNC=0xafbf0
OUT=0x10000000; LENP=0x12000000; ST=0x30000000
def unpack(path):
    d=open(path,"rb").read()
    mu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    for va,off,sz in SEGS:
        base=va&~0xfff; size=((va+sz-base)+0xfff)&~0xfff
        mu.mem_map(base,size); mu.mem_write(va,d[off:off+sz])
    mu.mem_map(OUT,0x200000); mu.mem_map(LENP,0x1000)
    mu.mem_map(ST,0x100000); mu.reg_write(UC_ARM_REG_SP,ST+0x80000)
    mu.reg_write(UC_ARM_REG_R0,SRC); mu.reg_write(UC_ARM_REG_R1,SRCLEN)
    mu.reg_write(UC_ARM_REG_R2,OUT); mu.reg_write(UC_ARM_REG_R3,LENP)
    mu.reg_write(UC_ARM_REG_LR,0xdeadbeef)
    try: mu.emu_start(FUNC,0xdeadbeef,count=50_000_000)
    except UcError: pass
    n=struct.unpack("<I",mu.mem_read(LENP,4))[0]
    return bytes(mu.mem_read(OUT,n)), n
res={}
for f in sorted(glob.glob("batch/so/*.so")):
    try:
        data,n=unpack(f)
        h=hashlib.sha256(data).hexdigest()
        res[h]=res.get(h,[0,None]); res[h][0]+=1; res[h][1]=data
        print("%-44s -> %d bytes sha256=%s"%(os.path.basename(f)[:42],n,h[:16]))
    except Exception as e:
        print("%-44s ERR %s"%(os.path.basename(f)[:42],e))
print("\n=== distinct outputs ===")
for h,(c,data) in res.items():
    print("  sha256",h,"count",c,"size",len(data))
    open("batch/out/%s.bin"%h[:16],"wb").write(data)
