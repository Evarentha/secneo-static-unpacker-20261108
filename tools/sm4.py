#!/usr/bin/env python3
#
# Standard SM4 Block Cipher Implementation
#
# Pure Python implementation of SM4 initialized with verified S-box and key parameters.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Provides 128-bit block encryption and decryption routines in ECB mode, matching the cryptographic parameters embedded within libDexHelper.so.
"""

import struct
_mod=None
def _load():
    global _mod,Sl,CK,FK
    _mod=open(__import__('os').path.join(__import__('os').path.dirname(__file__),'dec_payload.bin'),'rb').read()
    Sl=list(_mod[0x647b4:0x647b4+256])
    CK=list(struct.unpack("<32I",_mod[0x64734:0x64734+128]))
    FK=list(struct.unpack("<4I",_mod[0x87bc:0x87bc+16]))
_load()
def tau(a): return ((Sl[(a>>24)&255]<<24)|(Sl[(a>>16)&255]<<16)|(Sl[(a>>8)&255]<<8)|Sl[a&255])
def T(a):
    b=tau(a); return (b ^ ((b<<2|b>>30)&0xffffffff) ^ ((b<<10|b>>22)&0xffffffff) ^ ((b<<18|b>>14)&0xffffffff) ^ ((b<<24|b>>8)&0xffffffff))&0xffffffff
def Tp(a):
    b=tau(a); return (b ^ ((b<<13|b>>19)&0xffffffff) ^ ((b<<23|b>>9)&0xffffffff))&0xffffffff
def keyexp(key):
    K=[struct.unpack(">I",key[4*i:4*i+4])[0]^FK[i] for i in range(4)]; rk=[]
    for i in range(32): k=(K[i]^Tp(K[i+1]^K[i+2]^K[i+3]^CK[i]))&0xffffffff; K.append(k); rk.append(k)
    return rk
def dec(rk,c):
    X=list(struct.unpack(">4I",c))
    for i in range(32): X.append((X[i]^T(X[i+1]^X[i+2]^X[i+3]^rk[31-i]))&0xffffffff)
    return struct.pack(">4I",X[35],X[34],X[33],X[32])
def enc(rk,c):
    X=list(struct.unpack(">4I",c))
    for i in range(32): X.append((X[i]^T(X[i+1]^X[i+2]^X[i+3]^rk[i]))&0xffffffff)
    return struct.pack(">4I",X[35],X[34],X[33],X[32])
def dec_ecb(key,data):
    rk=keyexp(key); return b"".join(dec(rk,data[i:i+16]) for i in range(0,len(data),16))
