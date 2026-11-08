#!/usr/bin/env python3
#
# Generic MUTF-8 String Pool Parser
#
# Parses Dalvik MUTF-8 encoded string pools with uleb128 size decoding.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Iterates over raw Dalvik string pools, parsing lengths and MUTF-8 byte sequences.
"""

"""SecNeo dexdata0 payload: MUTF-8-correct string pool walker.
DEX string_data_item: uleb128(utf16_units) + MUTF-8 bytes + 0x00
ASCII==bytes only for ASCII; CJK strings break byte-count walking.
"""
import struct, sys

def uleb(p,o,L):
    r=0;s=0
    for i in range(5):
        if o+i>=L: return None,0
        b=p[o+i]; r|=(b&0x7f)<<s
        if not b&0x80: return r,i+1
        s+=7
    return None,0

def mutf8_item(p,o,L):
    """return (size, nbytes) or None"""
    ln,kl=uleb(p,o,L)
    if ln is None or ln>0xFFFF: return None
    i=o+kl; units=0
    while units<ln:
        if i>=L: return None
        b=p[i]
        if b<0x80: i+=1
        elif (b&0xE0)==0xC0: i+=2
        elif (b&0xF0)==0xE0: i+=3
        else: return None
        units+=1
    if i>=L or p[i]!=0: return None
    return (i+1-o, i-o-kl)

def walk(p,o,L,cap=500000):
    starts=[]
    while len(starts)<cap:
        r=mutf8_item(p,o,L)
        if r is None: break
        starts.append((o,r[1])); o+=r[0]
    return starts,o

if __name__=='__main__':
    Z=open('unpack/out/classes.orig.dex','rb').read()
    p=Z[0x4460:0x4460+0xCDE000]; L=len(p)
    # find longest chain start in the data-ish region
    best=(0,0,0)
    o=0x1a4000
    while o<0x1c0000:
        st,end=walk(p,o,L)
        if len(st)>best[0]: best=(len(st),o,end)
        o = st[-1][0]+1 if st else o+1
    print("longest chain:",best[0],"start",hex(best[1]),"end",hex(best[2]))
    st,end=walk(p,best[1],L)
    print("first 5:",[(hex(a),n) for a,n in st[:5]])
    print("last 3:",[(hex(a),n) for a,n in st[-3:]])
