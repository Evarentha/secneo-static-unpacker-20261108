#!/usr/bin/env python3
#
# Target Method Bytecode Extractor
#
# Isolates and dumps bytecode for targetMethod authentication routines.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Locates the method definitions and Dalvik bytecode specifically for target API method definitions (targetMethod).
"""

# Step 7: dex2 symbolic resolution + locate & decode the method that references /mdm/targetMethod.
#  * string map: pool2 walk is index-ordered -> idx -> string (no need for encrypted string_ids)
#  * type/proto/field/method ids: plaintext tables at 0x8B8000..
#  * code: plaintext in data tail; enclosing code_item found by header scan
import struct, io, json

data = open("unpack/out/app.dec.dex", "rb").read()
N = len(data)
NTYPE, NPROTO, NFIELD, NMETH = 5503, 6088, 27201, 30873
T_TYPE, T_PROTO, T_FIELD, T_METH = 0x8B8000, 0x8BD5FC, 0x8CF35C, 0x904564
TAIL = 0xA2EEB8

pool = json.load(io.open("unpack/out/pool2_walk.json", encoding="utf-8"))
S = [x["s"] for x in pool]
def s_of(i): return S[i] if 0 <= i < len(S) else f"<str{i}>"

type_str = []
for i in range(NTYPE):
    si = struct.unpack_from("<I", data, T_TYPE + 4*i)[0]
    type_str.append(s_of(si) if si < len(S) else f"<t{i}?{si}>")

def type_name(t): return type_str[t] if t < NTYPE else f"<type{t}>"

protos = [struct.unpack_from("<III", data, T_PROTO + 12*i) for i in range(NPROTO)]

def proto_params(p):
    """type_list at params_off (u4 size + u2[]), in the plaintext tail"""
    ret, off = protos[p][1], protos[p][2]
    if not off:
        return f"(){type_name(ret)}"
    if not (0 < off < N - 4):
        return f"(?){type_name(ret)}"
    n = struct.unpack_from("<I", data, off)[0]
    if n > 100: return f"(?){type_name(ret)}"
    ps = [type_name(struct.unpack_from("<H", data, off+4+2*k)[0]) for k in range(n)]
    return "(" + ",".join(ps) + ")" + type_name(ret)

def meth_sig(m):
    c, p, n = struct.unpack_from("<HHI", data, T_METH + 8*m)
    return f"{type_name(c)}->{s_of(n)}{proto_params(p)}"

def field_sig(f):
    c, t, n = struct.unpack_from("<HHI", data, T_FIELD + 8*f)
    return f"{type_name(c)}->{s_of(n)}:{type_name(t)}"

# ---------------- code_item helpers ----------------
def plausible_header(h):
    if h < 0 or h + 16 > N or h % 4: return None
    regs, ins, outs, tries, dbg, insns = struct.unpack_from("<HHHHII", data, h)
    if not (1 <= regs <= 255): return None
    if ins > regs or outs > 255: return None
    if tries > 20: return None
    if dbg and dbg >= N: return None
    if not (1 <= insns <= 30000): return None
    if h + 16 + 2*insns > N: return None
    return (regs, ins, outs, tries, dbg, insns)

def enclosing_code_item(pos, back=0x4000):
    best = None
    for h in range(pos - (pos % 4), pos - back, -4):
        ci = plausible_header(h)
        if not ci: continue
        start, insns = h + 16, ci[5]
        if start <= pos < start + 2*insns:
            if best is None or insns < best[1]: best = (h, insns, ci)
    # widen once if nothing found
    if best is None:
        for h in range(pos - (pos % 4), pos - 0x40000, -4):
            ci = plausible_header(h)
            if not ci: continue
            start, insns = h + 16, ci[5]
            if start <= pos < start + 2*insns:
                if best is None or insns < best[1]: best = (h, insns, ci)
    return best

SZ = {0x01:0,0x02:1,0x03:2,0x04:2,0x05:3,0x06:3,0x07:0,0x08:2,0x09:3,0x0a:2,
      0x0b:2,0x0c:2,0x0d:2,0x0e:0,0x0f:0,0x10:0,0x11:0,0x12:1,0x13:2,0x14:3,
      0x15:2,0x16:2,0x17:3,0x18:5,0x19:2,0x1a:2,0x1b:3,0x1c:2,0x1d:1,0x1e:1,
      0x1f:2,0x20:2,0x21:1,0x22:2,0x23:2,0x24:3,0x25:3,0x26:3,0x27:1,0x28:1,
      0x29:2,0x2a:3,0x2b:3,0x2c:3,0x2d:2,0x2e:2,0x2f:2,0x30:2,0x31:2,0x32:2,
      0x33:2,0x34:2,0x35:2,0x36:2,0x37:2,0x38:2,0x39:2,0x3a:2,0x3b:2,0x3c:2,
      0x3d:1,0x3e:1,0x3f:1,0x40:1,0x41:1,0x42:1,0x43:1,0x44:2,0x45:2,0x46:2,
      0x47:2,0x48:2,0x49:2,0x4a:2,0x4b:2,0x4c:2,0x4d:2,0x4e:2,0x4f:2,0x50:2,
      0x51:2,0x52:2,0x53:2,0x54:2,0x55:2,0x56:2,0x57:2,0x58:2,0x59:2,0x5a:2,
      0x5b:2,0x5c:2,0x5d:2,0x5e:2,0x5f:2,0x60:2,0x61:2,0x62:2,0x63:2,0x64:2,
      0x65:2,0x66:2,0x67:2,0x68:2,0x69:2,0x6a:2,0x6b:2,0x6c:2,0x6d:2,0x6e:3,
      0x6f:3,0x70:3,0x71:3,0x72:3,0x73:0,0x74:3,0x75:3,0x76:3,0x77:3,0x78:3,
      0x79:3,0x7a:2,0x7b:1,0x7c:1,0x7d:1,0x7e:1,0x7f:1,0x80:1,0x81:1,0x82:1,
      0x83:1,0x84:1,0x85:1,0x86:1,0x87:1,0x88:1,0x89:1,0x8a:1,0x8b:1,0x8c:1,
      0x8d:1,0x8e:1,0x8f:1,0x90:2,0x91:2,0x92:2,0x93:2,0x94:2,0x95:2,0x96:2,
      0x97:2,0x98:2,0x99:2,0x9a:2,0x9b:2,0x9c:2,0x9d:2,0x9e:2,0x9f:2,0xa0:2,
      0xa1:2,0xa2:2,0xa3:2,0xa4:2,0xa5:2,0xa6:2,0xa7:2,0xa8:2,0xa9:2,0xaa:2,
      0xab:2,0xac:2,0xad:2,0xae:2,0xaf:2,0xb0:1,0xb1:1,0xb2:1,0xb3:1,0xb4:1,
      0xb5:1,0xb6:1,0xb7:1,0xb8:1,0xb9:1,0xba:1,0xbb:1,0xbc:1,0xbd:1,0xbe:1,
      0xbf:1,0xc0:1,0xc1:1,0xc2:1,0xc3:1,0xc4:1,0xc5:1,0xc6:1,0xc7:1,0xc8:1,
      0xc9:1,0xca:1,0xcb:1,0xcc:1,0xcd:1,0xce:1,0xcf:1,0xd0:2,0xd1:2,0xd2:2,
      0xd3:2,0xd4:2,0xd5:2,0xd6:2,0xd7:2,0xd8:2,0xd9:2,0xda:2,0xdb:2,0xdc:2,
      0xdd:2,0xde:2,0xdf:2,0xe0:2,0xe1:2,0xe2:2,0xe3:2,0xe4:2,0xe5:2,0xe6:2,
      0xe7:2,0xe8:2,0xe9:2,0xea:2,0xeb:2,0xec:2,0xed:2,0xee:2,0xef:2,0xf0:2,
      0xf1:2,0xf2:2,0xf3:2,0xf4:2,0xf5:2,0xf6:2,0xf7:2,0xf8:2,0xf9:2,0xfa:2,
      0xfb:2,0xfc:2,0xfd:2,0xfe:2,0xff:2}

def decode(insns_start, insns_units, limit=4000, annotate=True):
    out = []
    o = insns_start; end = insns_start + 2*insns_units
    while o + 2 <= end and len(out) < limit:
        w = struct.unpack_from("<H", data, o)[0]; op = w & 0xff
        n = SZ.get(op)
        if n is None: n = 1
        if o + 2*(n+1) > end: break
        txt = None
        if annotate:
            if op == 0x1a:
                idx = struct.unpack_from("<H", data, o+2)[0]
                txt = f'const-string v{w>>8}, {s_of(idx)!r}'
            elif op == 0x1b:
                idx = struct.unpack_from("<I", data, o+2)[0]
                txt = f'const-string/jumbo v{w>>8}, {s_of(idx)!r}'
            elif 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
                mid = struct.unpack_from("<H", data, o+2)[0]
                nm = {0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",
                      0x71:"invoke-static",0x72:"invoke-interface",0x74:"invoke-virtual/range",
                      0x75:"invoke-super/range",0x76:"invoke-direct/range",
                      0x77:"invoke-static/range",0x78:"invoke-interface/range"}[op]
                txt = f"{nm} {meth_sig(mid)}" if mid < NMETH else f"{nm} <meth{mid}>"
            elif op in (0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d):
                fid = struct.unpack_from("<H", data, o+2)[0]
                txt = f"field-op {op:#04x} {field_sig(fid)}" if fid < NFIELD else None
            elif op == 0x22:   # new-instance 21c
                tidx = struct.unpack_from("<H", data, o+2)[0]
                txt = f"new-instance v{w>>8}, {type_name(tidx)}"
            elif op == 0x1c:   # const-class
                tidx = struct.unpack_from("<H", data, o+2)[0]
                txt = f"const-class v{w>>8}, {type_name(tidx)}"
        out.append((o, op, n, txt, data[o:o+2*(n+1)].hex(" ")))
        o += 2*(n+1)
    return out

# ---------------- find the targetMethod reference ----------------
def find_const_string(idx):
    res = []
    for base in range(TAIL, N, 0x40000):
        end = min(base + 0x40000, N)
        buf = data[base:end]
        for off in range(0, len(buf)-6, 2):
            w = buf[off] | (buf[off+1] << 8)
            if (w & 0xff) == 0x1a and (buf[off+2] | (buf[off+3] << 8)) == idx:
                res.append(base+off)
            elif (w & 0xff) == 0x1b:
                j = buf[off+2] | (buf[off+3] << 8) | (buf[off+4] << 16) | (buf[off+5] << 24)
                if j == idx: res.append(base+off)
    return res

TARGETS = {1934: "/mdm/targetMethod", 1909: "/mdm/dev/targetMethod", 1935: "/mdm/targetMethod_pre"}
for idx, name in TARGETS.items():
    pos = find_const_string(idx)
    print(f"\n===== const-string #{idx} {name}: {len(pos)} occurrence(s) =====")
    for p in pos:
        ci = enclosing_code_item(p)
        if not ci:
            print(f"  @{p:#x}: no enclosing code_item found")
            continue
        h, insns, (regs, ins, outs, tries, dbg, _) = ci
        print(f"  @{p:#x} in code_item {h:#x} regs={regs} ins={ins} outs={outs} tries={tries} "
              f"debug_off={dbg:#x} insns_units={insns} (+{(p-h-16)//2} units from start)")
        dec = decode(h+16, insns)
        ctx = [d for d in dec if abs(d[0]-p) <= 120]
        for o, op, n, txt, raw in ctx:
            mark = " <<<" if o == p else ""
            print(f"      {o:#08x} {raw:18s} {txt or ''}{mark}")
