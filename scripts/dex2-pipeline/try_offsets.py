#!/usr/bin/env python3
#
# DEX Header Candidate Offset Evaluator
#
# Tests candidate base offsets against DEX header validation rules.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Automates validation of candidate offsets against expected DEX header fields.
"""

import zipfile,struct,sys
from unicorn import *
from unicorn.arm_const import *
APK=r"E:/Team/Project/日志/apk/6.0-1/管控平台_v5.6.10.4.xkt.apk"
z=zipfile.ZipFile(APK); so=z.read("lib/armeabi-v7a/libDexHelper.so"); dex=z.read("classes.dex")
SEGS=[(0x0,0x0,0x8c671),(0x8e460,0x8d460,0x8d14),(0xaf174,0x96174,0xcc8)]
FUNC=0xafbf0
def run(off,ln):
    mu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    for va,o,sz in SEGS:
        base=va&~0xfff; size=((va+sz-base)+0xfff)&~0xfff
        mu.mem_map(base,size); mu.mem_write(va,so[o:o+sz])
    IN=0x08000000; bufsz=((ln+0x100000)+0xfff)&~0xfff
    mu.mem_map(IN,bufsz); mu.mem_write(IN,dex[off:off+ln])
    OUT=0x20000000; mu.mem_map(OUT,0x4000000)
    LENP=0x12000000; mu.mem_map(LENP,0x1000)
    ST=0x30000000; mu.mem_map(ST,0x100000); mu.reg_write(UC_ARM_REG_SP,ST+0x80000)
    mu.reg_write(UC_ARM_REG_R0,IN); mu.reg_write(UC_ARM_REG_R1,ln)
    mu.reg_write(UC_ARM_REG_R2,OUT); mu.reg_write(UC_ARM_REG_R3,LENP)
    mu.reg_write(UC_ARM_REG_LR,0xdeadbeef)
    try: mu.emu_start(FUNC,0xdeadbeef,count=100_000_000)
    except UcError as e: return None,str(e)
    n=struct.unpack("<I",mu.mem_read(LENP,4))[0]
    if 0<n<0x4000000:
        data=bytes(mu.mem_read(OUT,min(n,64)))
        return data,n
    return None,("len="+str(n))
for off in (0x4400,0x4440,0x4454,0x445C,0x445D,0x4460,0x4464,0x4490):
    ln=len(dex)-off
    d,n=run(off,ln)
    print(f"off={hex(off)} len={ln} -> {n if isinstance(n,str) else ('OK n=0x%x'%n)} head={(d[:12].hex() if d else '')}")
