#!/usr/bin/env python3
#
# DEX2 string_ids Assembler & Checksum Rebuilder
#
# Replaces encrypted string_ids with mapped pool offsets and fixes checksums.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Replaces the SM4-encrypted string_ids table with computed pool offsets, updates header metadata, and recalculates Adler32 and SHA-1 signatures.
"""

"""
rebuild_dex2_stringids.py — the final mechanical step of the dex2 unpack.

Input : a 129,552-byte file holding dex2's decrypted string_ids
        (32,388 little-endian u4 file offsets into the string-data pool).
        Sources: frida_stringids_dump.js output, or your own decryptor.
Output: unpack/out/app2.final.dex  — dex2 with a valid header, ready for JADX.

The script is strict on purpose: it refuses to emit a dex unless the plaintext
satisfies every invariant the format guarantees, so a wrong decryption can never
silently produce a dex whose class/method names are garbage.

Invariants checked
  1. exactly 32,388 entries, every one inside the pool range [0x961B68, 0xA2EEB8)
  2. all offsets distinct
  3. the set of offsets equals the set produced by walking the pool
  4. strings in string_ids order are non-decreasing in MUTF-8 byte order
     (dex requires string_ids to be sorted; this is the strongest oracle)
"""

import argparse
import os
import struct
import sys

POOL_START = 0x961B68
POOL_END = 0xA2EEB8
N_STRINGS = 32388
TYPE_IDS_OFF = 0x8B8000
TYPE_IDS_SIZE = 5503
STRING_IDS_OFF = 0x8985F0        # where the table lives inside the payload
CLASS_DEFS_OFF = 0x940A2C
CLASS_DEFS_SIZE = 4233


def walk_pool(data):
    """Return [(offset, raw_bytes)] for every string in the plaintext pool."""
    items = []
    p = POOL_START
    while p < POOL_END:
        start = p
        # uleb128 length in UTF-16 code units
        length = 0
        shift = 0
        while True:
            if p >= len(data):
                raise ValueError("pool walk ran past end of file")
            b = data[p]
            p += 1
            length |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        # payload is length*2 bytes for MUTF-8 up to 0x7FFF, else more for
        # surrogate pairs; the walk below is byte-accurate via the NUL terminator
        end = p
        units = 0
        while units < length:
            if end >= len(data):
                raise ValueError("string ran past end of file")
            if data[end] == 0:
                break
            units += 1
            end += 1
        while end < len(data) and data[end] != 0:
            end += 1
        items.append((start, data[p:end], length))
        p = end + 1
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", required=True, help="decrypted string_ids, 129552 bytes")
    ap.add_argument("--dex", default="unpack/out/app.dec.dex",
                    help="payload with plaintext string-data pool")
    ap.add_argument("--out", default="unpack/out/app2.final.dex")
    ap.add_argument("--allow-unsorted", action="store_true",
                    help="skip invariant 4 (only if you know the order differs)")
    args = ap.parse_args()

    ids_raw = open(args.ids, "rb").read()
    if len(ids_raw) != N_STRINGS * 4:
        sys.exit(f"FAIL size: got {len(ids_raw)}, want {N_STRINGS*4}")

    ids = list(struct.unpack(f"<{N_STRINGS}I", ids_raw))

    bad = [i for i, v in enumerate(ids) if not (POOL_START <= v < POOL_END)]
    if bad:
        sys.exit(f"FAIL range: {len(bad)} entries outside pool, first idx {bad[0]} "
                 f"= 0x{ids[bad[0]]:x}")

    if len(set(ids)) != N_STRINGS:
        sys.exit(f"FAIL distinct: only {len(set(ids))} unique of {N_STRINGS}")

    data = bytearray(open(args.dex, "rb").read())
    pool = walk_pool(data)
    pool_offsets = {off for off, _, _ in pool}
    if set(ids) != pool_offsets:
        missing = len(pool_offsets - set(ids))
        extra = len(set(ids) - pool_offsets)
        sys.exit(f"FAIL set: {missing} pool offsets unreferenced, {extra} ids not in pool")

    if not args.allow_unsorted:
        by_off = {off: raw for off, raw, _ in pool}
        prev = b""
        for i, off in enumerate(ids):
            cur = by_off[off]
            if cur < prev:
                sys.exit(f"FAIL sorted: index {i} breaks MUTF-8 order "
                         f"({cur[:24]!r} < {prev[:24]!r})")
            prev = cur

    # Patch header + table. Everything else (type_ids, method_ids, class_defs,
    # code_items) was already recovered in plaintext by the earlier passes.
    struct.pack_into("<I", data, 0x38, N_STRINGS)          # string_ids_size
    struct.pack_into("<I", data, 0x3C, STRING_IDS_OFF)     # string_ids_off
    struct.pack_into("<I", data, 0x40, TYPE_IDS_SIZE)      # type_ids_size
    struct.pack_into("<I", data, 0x44, TYPE_IDS_OFF)       # type_ids_off
    struct.pack_into("<I", data, 0x60, CLASS_DEFS_SIZE)    # class_defs_size
    struct.pack_into("<I", data, 0x64, CLASS_DEFS_OFF)     # class_defs_off
    struct.pack_into("<I", data, 0x20, len(data))          # file_size

    data[STRING_IDS_OFF:STRING_IDS_OFF + N_STRINGS * 4] = ids_raw

    # adler32 checksum (0x08) and sha1 signature (0x0C..0x1F)
    import zlib
    data[0x0C:0x20] = b"\x00" * 20
    struct.pack_into("<I", data, 0x08, 0)
    sig = __import__("hashlib").sha1(bytes(data[0x20:])).digest()
    data[0x0C:0x20] = sig
    struct.pack_into("<I", data, 0x08, zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    open(args.out, "wb").write(data)

    import hashlib
    print(f"OK wrote {args.out} ({len(data)} bytes)")
    print(f"   sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"   string_ids {N_STRINGS} @0x{STRING_IDS_OFF:x}, type_ids {TYPE_IDS_SIZE} @0x{TYPE_IDS_OFF:x}")
    print("   next: jadx --no-res --no-imports -d unpack/out/jadx2 " + args.out)


if __name__ == "__main__":
    main()
