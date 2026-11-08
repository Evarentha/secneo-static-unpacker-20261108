#!/usr/bin/env python3
#
# Dalvik Bytecode Instruction Decoder
#
# Decodes raw Dalvik bytecode into human-readable opcode sequences.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Parses bytecode instructions and formats register operations, branching targets, and literal references.
"""

# Step 9: decode the exact methods that reference /mdm/loginInitV3 using the VALIDATED
# code_item table; dump all const-string / invoke / field ops around the call.
import struct, io, json

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
NTYPE, NPROTO, NFIELD, NMETH = 5503, 6088, 27201, 30873
T_TYPE, T_PROTO, T_FIELD, T_METH = 0x8B8000, 0x8BD5FC, 0x8CF35C, 0x904564
pool = json.load(io.open("unpack/out/pool2_walk.json", encoding="utf-8"))
S = [x["s"] for x in pool]
def s_of(i): return S[i] if 0 <= i < len(S) else f"<str{i}>"
type_str = [s_of(struct.unpack_from("<I", data, T_TYPE+4*i)[0]) for i in range(NTYPE)]
def tn(t): return type_str[t] if t < NTYPE else f"<type{t}>"
protos = [struct.unpack_from("<III", data, T_PROTO+12*i) for i in range(NPROTO)]
def proto_sig(p):
    ret, off = protos[p][1], protos[p][2]
    if not off: return f"(){tn(ret)}"
    n = struct.unpack_from("<I", data, off)[0]
    if n > 60: return f"(?){tn(ret)}"
    return "(" + ",".join(tn(struct.unpack_from("<H", data, off+4+2*k)[0]) for k in range(n)) + ")" + tn(ret)
def meth_sig(m):
    c, p, n = struct.unpack_from("<HHI", data, T_METH+8*m)
    return f"{tn(c)}->{s_of(n)}{proto_sig(p)}"
def field_sig(f):
    c, t, n = struct.unpack_from("<HHI", data, T_FIELD+8*f)
    return f"{tn(c)}->{s_of(n)}:{tn(t)}"

code_items = json.load(open("unpack/out/dex2_code_items.json"))
idx_by_start = {c[0]: c for c in code_items}
starts = sorted(idx_by_start)

def enclosing(pos):
    best = None
    for s in starts:
        h, regs, ins, outs, tries, dbg, units = idx_by_start[s]
        if h + 16 <= pos < h + 16 + 2*units:
            if best is None or h > best[0]: best = (h, regs, ins, outs, tries, dbg, units)
    return best

SZ = {0x00:0,0x01:0,0x02:1,0x03:1,0x04:1,0x05:1,0x06:1,0x07:0,0x08:1,0x09:1,0x0a:1,
 0x0b:1,0x0c:1,0x0d:1,0x0e:0,0x0f:0,0x10:0,0x11:0,0x12:0,0x13:1,0x14:1,0x15:1,
 0x16:1,0x17:1,0x18:2,0x19:1,0x1a:1,0x1b:2,0x1c:1,0x1d:0,0x1e:0,0x1f:1,0x20:1,
 0x21:0,0x22:1,0x23:1,0x24:2,0x25:2,0x26:2,0x27:0,0x28:0,0x29:1,0x2a:2,0x2b:2,
 0x2c:2,0x2d:1,0x2e:1,0x2f:1,0x30:1,0x31:1,0x32:1,0x33:1,0x34:1,0x35:1,0x36:1,
 0x37:1,0x38:1,0x39:1,0x3a:1,0x3b:1,0x3c:1,0x44:1,0x45:1,0x46:1,0x47:1,0x48:1,
 0x49:1,0x4a:1,0x4b:1,0x4c:1,0x4d:1,0x4e:1,0x4f:1,0x50:1,0x51:1,0x52:1,0x53:1,
 0x54:1,0x55:1,0x56:1,0x57:1,0x58:1,0x59:1,0x5a:1,0x5b:1,0x5c:1,0x5d:1,0x5e:1,
 0x5f:1,0x60:1,0x61:1,0x62:1,0x63:1,0x64:1,0x65:1,0x66:1,0x67:1,0x68:1,0x69:1,
 0x6a:1,0x6b:1,0x6c:1,0x6d:1,0x6e:2,0x6f:2,0x70:2,0x71:2,0x72:2,0x74:2,0x75:2,
 0x76:2,0x77:2,0x78:2,0x90:1,0x91:1,0x92:1,0x93:1,0x94:1,0x95:1,0x96:1,0x97:1,
 0x98:1,0x99:1,0x9a:1,0x9b:1,0x9c:1,0x9d:1,0x9e:1,0x9f:1,0xa0:1,0xa1:1,0xa2:1,
 0xa3:1,0xa4:1,0xa5:1,0xa6:1,0xa7:1,0xa8:1,0xa9:1,0xaa:1,0xab:1,0xac:1,0xad:1,
 0xae:1,0xaf:1,0xd0:1,0xd1:1,0xd2:1,0xd3:1,0xd4:1,0xd5:1,0xd6:1,0xd7:1,0xd8:1,
 0xd9:1,0xda:1,0xdb:1,0xdc:1,0xdd:1,0xde:1,0xdf:1,0xe0:1,0xe1:1,0xe2:1,0xfa:3,
 0xfb:3,0xfc:2,0xfd:2,0xfe:1,0xff:1}
for op in list(range(0xb0,0xd0)): SZ[op] = 0
for op in list(range(0x7b,0x90)): SZ[op] = 0
for op in [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d]: SZ[op] = SZ.get(op,0)
INV = {0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",0x71:"invoke-static",
       0x72:"invoke-interface",0x74:"invoke-virtual/range",0x75:"invoke-super/range",
       0x76:"invoke-direct/range",0x77:"invoke-static/range",0x78:"invoke-interface/range"}

def decode_method(h, units):
    o, end = h+16, h+16+2*units
    rows = []
    while o < end:
        w = struct.unpack_from("<H", data, o)[0]; op = w & 0xff
        n = SZ.get(op, 0)
        txt = ""
        if op == 0x1a:
            txt = f"const-string v{w>>8}, {s_of(struct.unpack_from('<H', data, o+2)[0])!r}"
        elif op == 0x1b:
            txt = f"const-string/jumbo v{w>>8}, {s_of(struct.unpack_from('<I', data, o+2)[0])!r}"
        elif op in INV:
            txt = f"{INV[op]} {meth_sig(struct.unpack_from('<H', data, o+2)[0])}"
        elif 0x52 <= op <= 0x6d:
            txt = f"field[{op:#04x}] {field_sig(struct.unpack_from('<H', data, o+2)[0])}"
        elif op == 0x22:
            txt = f"new-instance v{w>>8}, {tn(struct.unpack_from('<H', data, o+2)[0])}"
        elif op == 0x1c:
            txt = f"const-class v{w>>8}, {tn(struct.unpack_from('<H', data, o+2)[0])}"
        elif op == 0x18:
            pass
        rows.append((o, op, data[o:o+2*(n+1)].hex(" "), txt))
        o += 2*(n+1)
    return rows

HITS = {1934:"/mdm/loginInitV3", 1909:"/mdm/dev/loginInitV3", 1935:"/mdm/loginInitV3_pre"}
for idx, name in HITS.items():
    # re-locate const-string hits
    pos = []
    for base in range(0xA2EEB8, N, 0x40000):
        end = min(base+0x40000, N); buf = data[base:end]
        for off in range(0, len(buf)-4, 2):
            if (buf[off] & 0xff) == 0x1a and (buf[off+2] | (buf[off+3] << 8)) == idx:
                pos.append(base+off)
    print(f"\n############ #{idx} {name}  hits={[hex(p) for p in pos]}")
    for p in pos:
        ci = enclosing(p)
        if not ci:
            print(f"  @{p:#x}: NOT inside any validated code_item"); continue
        h, regs, ins, outs, tries, dbg, units = ci
        print(f"  @{p:#x} -> code_item {h:#x} regs={regs} ins={ins} outs={outs} tries={tries} "
              f"debug_info_off={dbg:#x} units={units} ({2*units} bytes)")
        for o, op, raw, txt in decode_method(h, units):
            mark = "   <<<<< HIT" if o == p else ""
            print(f"      {o:#08x} {raw:16s} {txt}{mark}")
