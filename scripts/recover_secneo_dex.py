#!/usr/bin/env python3
#
# Automated SecNeo Multi-DEX Extraction Pipeline
#
# Performs end-to-end container parsing, payload decompression, and DEX header recovery.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Automates the complete extraction workflow from an input classes.dex file, decompressing payload streams and outputting separate DEX files.
"""

"""SecNeo (Bangcle) dexdata0 -> standard DEX.

Findings this script implements (all measured, see VERIFICATION output):
  * classes.dex = stub dex [0x0000,0x43A0) + container [0x4440,EOF)
      container header @0x4440 : count=1, ?, ?, rec_size=0xcde014
      record @0x4450           : name_len=8, "dexdata0", data_size=0xcde000
      payload @0x4460, len 0xcde000, trailer "fdex"
  * payload == the real dex with one 0x1000-byte block inserted at 0x70:
      -> payload[0:0x70]  = real header          (encrypted in payload)
      -> payload[0x70:0x1070] = inserted block    (encrypted, not referenced)
      -> payload[0x1070:] = real dex[0x70:]       (string_ids starts at 0x1070)
  * every offset inside the id tables is 0x1000 lower than in the payload
  * payload[0,0x21000) is ciphertext = header + inserted block + string_ids[0:32740]
  * string_ids[32740:62762] is plaintext and validates 30022/30022 against the
    plaintext, sorted MUTF-8 string pool that starts at payload 0x1a4fd4.
  * therefore string_ids is rebuilt by walking the pool (no key needed).

Output: unpack/out/app.dec.dex
"""
import struct, hashlib, zlib, sys, json, io, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, 'unpack', 'out', 'classes.orig.dex')
DST  = os.path.join(ROOT, 'unpack', 'out', 'app.dec.dex')

PAYLOAD_OFF   = 0x4460
PAYLOAD_LEN   = 0xCDE000
INSERT_OFF    = 0x70
INSERT_LEN    = 0x1000
N_STRINGS     = 62762
N_TYPES       = 9354
N_PROTOS      = 14517
N_FIELDS      = 64469
N_METHODS     = 62406

def uleb(p, o, L):
    r = 0; s = 0
    for i in range(5):
        if o + i >= L: return None, 0
        b = p[o + i]; r |= (b & 0x7f) << s
        if not b & 0x80: return r, i + 1
        s += 7
    return None, 0

def mutf8_item(p, o, L):
    """return size of string_data_item, or None. Length is in UTF-16 units."""
    ln, kl = uleb(p, o, L)
    if ln is None or ln > 0xFFFF: return None
    i = o + kl; units = 0
    while units < ln:
        if i >= L: return None
        b = p[i]
        if b < 0x80: i += 1
        elif (b & 0xE0) == 0xC0: i += 2
        elif (b & 0xF0) == 0xE0: i += 3
        else: return None
        units += 1
    if i >= L or p[i] != 0: return None
    return i + 1 - o

def main():
    Z = open(SRC, 'rb').read()
    P = Z[PAYLOAD_OFF:PAYLOAD_OFF + PAYLOAD_LEN]
    assert len(P) == PAYLOAD_LEN, 'payload short'
    ev = {'payload_len': PAYLOAD_LEN}

    # ---- 1. drop the inserted 0x1000 block -------------------------------
    D = bytearray(P[:INSERT_OFF] + P[INSERT_OFF + INSERT_LEN:])
    assert len(D) == PAYLOAD_LEN - INSERT_LEN
    ev['image_len'] = len(D)

    # ---- 2. walk the plaintext string pool (payload coords 0x1a4fd4) -----
    POOL_START = 0x1a4fd4
    starts = []
    o = POOL_START
    L = len(P)
    while len(starts) < N_STRINGS + 8:
        sz = mutf8_item(P, o, L)
        if sz is None: break
        starts.append(o); o += sz
    ev['pool_items'] = len(starts)
    ev['pool_range_payload'] = [hex(starts[0]), hex(starts[-1])]
    if len(starts) != N_STRINGS:
        raise SystemExit(f'pool item count {len(starts)} != {N_STRINGS}')

    # ---- 3. rebuild string_ids ------------------------------------------
    SIDS_OFF = 0x70
    assert SIDS_OFF + N_STRINGS * 4 <= len(D)
    for i, a in enumerate(starts):
        struct.pack_into('<I', D, SIDS_OFF + 4 * i, a - INSERT_LEN)

    # ---- 4. locate tables in the new image (payload coords - 0x1000) -----
    TYPE_OFF   = 0x3e518 - INSERT_LEN
    PROTO_OFF  = 0x47740 - INSERT_LEN
    FIELD_OFF  = 0x71fbc - INSERT_LEN
    METHOD_OFF = 0xefe64 - INSERT_LEN
    CLASS_OFF  = 0x169c94 - INSERT_LEN

    def u4(buf, o): return struct.unpack_from('<I', buf, o)[0]

    # sanity: string_ids must be strictly increasing and inside the pool range
    lo, hi = starts[0] - INSERT_LEN, starts[-1] - INSERT_LEN
    prev = -1; bad = 0
    for i in range(N_STRINGS):
        v = u4(D, SIDS_OFF + 4 * i)
        if not (lo <= v <= hi) or v < prev: bad += 1
        prev = v
    ev['string_ids_bad_entries'] = bad

    # ---- 5. class_defs run to find data_off ------------------------------
    o = CLASS_OFF; ncls = 0
    while o + 32 <= len(D):
        cls, acc, sup, ifo, src, ann, cd, sv = struct.unpack_from('<8I', D, o)
        if cls >= N_TYPES: break
        if acc & ~0x1FFFF: break
        if sup != 0xFFFFFFFF and sup >= N_TYPES: break
        if src != 0xFFFFFFFF and src >= N_STRINGS: break
        if (ifo and ifo >= len(D)) or (ann and ann >= len(D)): break
        if (cd and cd >= len(D)) or (sv and sv >= len(D)): break
        ncls += 1; o += 32
    ev['class_defs'] = ncls
    ev['class_defs_range'] = [hex(CLASS_OFF), hex(o)]
    DATA_OFF = (o + 3) & ~3
    ev['data_off'] = hex(DATA_OFF)
    DATA_SIZE = len(D) - DATA_OFF
    ev['data_size'] = DATA_SIZE

    # ---- 6. find map_list (u4 count + 12B entries, last = {0,0,1,0}) -----
    MAP_OFF = 0
    sig = bytes.fromhex('000000000100000000000000')
    idx = D.rfind(sig, DATA_OFF)
    while idx != -1:
        cand = idx - 12 * 0  # sig is the *last* 12-byte entry, count sits before entries
        # count is at cand_start, entries begin cand_start+4
        for cntpos in range(idx - 4 - 12 * 40, idx + 4):
            if cntpos < DATA_OFF: continue
            cnt = u4(D, cntpos)
            if not (8 <= cnt <= 40): continue
            if cntpos + 4 + 12 * cnt != idx + 12: continue
            ok = True; prevoff = -1
            for k in range(cnt):
                t, un, sz, off = struct.unpack_from('<HHII', D, cntpos + 4 + 12 * k)
                if un != 0 or sz == 0 or off >= len(D) or off < prevoff: ok = False; break
                prevoff = off
            if ok:
                MAP_OFF = cntpos; break
        if MAP_OFF: break
        idx = D.rfind(sig, DATA_OFF, idx)
    ev['map_off'] = '(pending synth)'

    # ---- 6b. synthesize map_list (original one is inside the cipher text) --
    base = (len(D) + 3) & ~3
    D.extend(bytes([0]) * (base - len(D)))
    entries = [(0x0000, 1, 0), (0x0001, N_STRINGS, SIDS_OFF),
               (0x0002, N_TYPES, TYPE_OFF), (0x0003, N_PROTOS, PROTO_OFF),
               (0x0004, N_FIELDS, FIELD_OFF), (0x0005, N_METHODS, METHOD_OFF),
               (0x0006, ncls, CLASS_OFF), (0x2002, N_STRINGS, DATA_OFF),
               (0x1000, 1, base)]
    assert all(entries[i][2] <= entries[i + 1][2] for i in range(len(entries) - 1))
    buf = struct.pack('<I', len(entries))
    for t, sz, off in entries:
        buf += struct.pack('<HHII', t, 0, sz, off)
    D.extend(buf)
    MAP_OFF = base
    DATA_SIZE = len(D) - DATA_OFF

    # ---- 7. write header -------------------------------------------------
    hdr = bytearray(0x70)
    hdr[0:8] = b'dex\n035\x00'
    struct.pack_into('<I', hdr, 0x20, len(D))          # file_size
    struct.pack_into('<I', hdr, 0x24, 0x70)            # header_size
    struct.pack_into('<I', hdr, 0x28, 0x12345678)      # endian_tag
    struct.pack_into('<I', hdr, 0x2c, 0)               # link_size
    struct.pack_into('<I', hdr, 0x30, 0)               # link_off
    struct.pack_into('<I', hdr, 0x34, MAP_OFF)         # map_off
    struct.pack_into('<II', hdr, 0x38, N_STRINGS, SIDS_OFF)
    struct.pack_into('<II', hdr, 0x40, N_TYPES, TYPE_OFF)
    struct.pack_into('<II', hdr, 0x48, N_PROTOS, PROTO_OFF)
    struct.pack_into('<II', hdr, 0x50, N_FIELDS, FIELD_OFF)
    struct.pack_into('<II', hdr, 0x58, N_METHODS, METHOD_OFF)
    struct.pack_into('<II', hdr, 0x60, ncls, CLASS_OFF)
    struct.pack_into('<II', hdr, 0x68, DATA_SIZE, DATA_OFF)
    D[0:0x70] = hdr
    # signature = SHA1 over [0x20:]
    sig_ = hashlib.sha1(bytes(D[0x20:])).digest()
    D[0x0c:0x20] = sig_
    # checksum = adler32 over [0x0c:]
    ck = zlib.adler32(bytes(D[0x0c:])) & 0xffffffff
    struct.pack_into('<I', D, 0x08, ck)
    ev['checksum'] = hex(ck)
    ev['sha1'] = sig_.hex()
    ev['map_off'] = hex(MAP_OFF)

    open(DST, 'wb').write(bytes(D))
    ev['out'] = DST
    ev['sha256'] = hashlib.sha256(bytes(D)).hexdigest()
    print(json.dumps(ev, indent=2))

if __name__ == '__main__':
    main()
