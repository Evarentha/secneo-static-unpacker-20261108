#!/usr/bin/env python3
#
# DEX2 Assembly Builder
#
# Assembles decompressed DEX2 segments into an aligned Dalvik image.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Alternative assembly utility combining fragmented DEX sections into a cohesive Dalvik executable file.
"""

"""Rebuild the second packed dex (dexdata0 part 2) as a standalone dex.

Layout measured from the payload (offset-preserving; data region is shared):
  0x000000 header            (rebuilt here; original is ciphertext)
  0x000070 string_ids        (32,388 entries rebuilt from the plaintext pool @0x961b68)
  0x8b8000 type_ids          (N2T entries, plaintext)
  0x8bd5fc proto_ids         (6,088 entries)
  0x8cf35c field_ids         (27,201 entries)
  0x904564 method_ids        (30,873 entries)
  0x940a2c class_defs        (4,233 entries -> 0x961b4c)
  0x961b68 string pool       (32,388 sorted MUTF-8 items, plaintext)
"""
import struct, hashlib, zlib, sys, json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT,'unpack','out','classes.orig.dex')
OUT  = os.path.join(ROOT,'unpack','out','app.dec2.dex')

N2S=32388; N2T=int(sys.argv[1]) if len(sys.argv)>1 else 5503
NP=6088; NF=27201; NM=30873; NC=4233
T2=0x8b8000; P2=0x8bd5fc; F2=0x8cf35c; M2=0x904564; C2=0x940a2c
POOL=0x961b68; DATA=0x196eb8

def uleb(p,o,L):
    r=0;s=0
    for i in range(5):
        b=p[o+i]; r|=(b&0x7f)<<s
        if not b&0x80: return r,i+1
        s+=7
    return None,0
def msz(p,o,L):
    ln,kl=uleb(p,o,L)
    if ln is None or ln>0xFFFF: return None
    i=o+kl;u=0
    while u<ln:
        if i>=L: return None
        b=p[i]
        if b<0x80: i+=1
        elif (b&0xE0)==0xC0: i+=2
        elif (b&0xF0)==0xE0: i+=3
        else: return None
        u+=1
    if i>=L or p[i]!=0: return None
    return i+1-o

Z=open(SRC,'rb').read()
P=Z[0x4460:0x4460+0xCDE000]
L=len(P)
D=bytearray(P[:0x70]+P[0x1070:])   # drop the 0x1000 inserted block -> same coord system as dex1
starts=[];o=POOL
while len(starts)<N2S+8:
    s=msz(D,o,L)
    if s is None: break
    starts.append(o); o+=s
assert len(starts)==N2S, (len(starts),N2S)
assert starts[0]==POOL
for i,a in enumerate(starts): struct.pack_into('<I',D,0x70+4*i,a)

# synthetic map_list appended at end
base=(len(D)+3)&~3
D.extend(b'\x00'*(base-len(D)))
entries=[(0x0000,1,0),(0x0001,N2S,0x70),(0x0002,N2T,T2),(0x0003,NP,P2),
         (0x0004,NF,F2),(0x0005,NM,M2),(0x0006,NC,C2),(0x2002,N2S,POOL),(0x1000,1,base)]
assert all(entries[i][2]<=entries[i+1][2] for i in range(len(entries)-1))
buf=struct.pack('<I',len(entries))
for t,sz,off in entries: buf+=struct.pack('<HHII',t,0,sz,off)
D.extend(buf)

hdr=bytearray(0x70); hdr[0:8]=b'dex\n035\x00'
struct.pack_into('<I',hdr,0x20,len(D)); struct.pack_into('<I',hdr,0x24,0x70)
struct.pack_into('<I',hdr,0x28,0x12345678)
struct.pack_into('<I',hdr,0x34,base)
struct.pack_into('<II',hdr,0x38,N2S,0x70)
struct.pack_into('<II',hdr,0x40,N2T,T2)
struct.pack_into('<II',hdr,0x48,NP,P2)
struct.pack_into('<II',hdr,0x50,NF,F2)
struct.pack_into('<II',hdr,0x58,NM,M2)
struct.pack_into('<II',hdr,0x60,NC,C2)
struct.pack_into('<II',hdr,0x68,len(D)-DATA,DATA)
D[0:0x70]=hdr
D[0x0c:0x20]=hashlib.sha1(bytes(D[0x20:])).digest()
struct.pack_into('<I',D,0x08,zlib.adler32(bytes(D[0x0c:]))&0xffffffff)
open(OUT,'wb').write(bytes(D))
print(json.dumps({'out':OUT,'size':len(D),'N2T':N2T,'sha256':hashlib.sha256(bytes(D)).hexdigest()},indent=2))
