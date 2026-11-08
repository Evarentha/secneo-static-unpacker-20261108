#!/usr/bin/env python3
#
# Emulation Fault Injection & Debugger
#
# Diagnoses memory faults and unmapped accesses during Unicorn emulation.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Traces register states and faulting memory addresses during ARM emulation sessions.
"""

import zipfile,struct
from unicorn import *
from unicorn.arm_const import *
APK=r"E:/Team/Project/日志/apk/6.0-1/管控平台_v5.6.10.4.xkt.apk"
z=zipfile.ZipFile(APK); so=z.read("lib/armeabi-v7a/libDexHelper.so"); dex=z.read("classes.dex")
SEGS=[(0x0,0x0,0x8c671),(0x8e460,0x8d460,0x8d14),(0xaf174,0x96174,0xcc8)]
mu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
for va,o,sz in SEGS:
    base=va&~0xfff; size=((va+sz-base)+0xfff)&~0xfff
    mu.mem_map(base,size); mu.mem_write(va,so[o:o+sz])
off=0x4460; ln=len(dex)-off
IN=0x08000000; mu.mem_map(IN,((ln+0x100000)+0xfff)&~0xfff); mu.mem_write(IN,dex[off:off+ln])
OUT=0x20000000; mu.mem_map(OUT,0x4000000)
LENP=0x12000000; mu.mem_map(LENP,0x1000)
ST=0x30000000; mu.mem_map(ST,0x100000); mu.reg_write(UC_ARM_REG_SP,ST+0x80000)
mu.reg_write(UC_ARM_REG_R0,IN); mu.reg_write(UC_ARM_REG_R1,ln)
mu.reg_write(UC_ARM_REG_R2,OUT); mu.reg_write(UC_ARM_REG_R3,LENP)
mu.reg_write(UC_ARM_REG_LR,0xdeadbeef)
try: mu.emu_start(FUNC:=0xafbf0,0xdeadbeef,count=5_000_000)
except UcError as e:
    pc=mu.reg_read(UC_ARM_REG_PC)
    print("fault:",e,"PC=0x%x"%pc)
    for r in ("R0","R1","R2","R3","R4","R5","R6","R7","R8","R9","R10","R11","R12"):
        try: print(" ",r,hex(mu.reg_read(getattr(UC_ARM_REG_'+r if False else UC_ARM_REG_'+'',r))))
        except Exception: pass
