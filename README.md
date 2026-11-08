# SecNeo-Unpack

Static reverse engineering toolkit and unpacker pipeline for Bangcle SecNeo (梆梆加固) Android packer variants (`com.secneo.apkwrapper` / `libDexHelper.so`).

Targets APKs packed with SecNeo where payload DEX files are embedded in a custom `dexdata0` container within `classes.dex`, protected by a self-extracting native ELF runtime (`libDexHelper.so`) that hooks ART (`art::DexFileLoader::OpenCommon` / `art::DexFile::OpenMemory`) and encrypts `string_ids` tables via SM4.

All primary extraction and reconstruction steps operate **offline and statically** via Unicorn ARM emulation, custom DEX parsing, and pool mapping without requiring a rooted target device or active Frida instrumentation.

---

## Architecture Overview

```
APK Root
│
├── classes.dex (Stub DEX + Appended Payload Container)
│   ├── [0x0000..0x43A0]  Stub Dalvik Header & Classes (com.secneo.apkwrapper.AW)
│   └── [0x4400..EOF]     SecNeo Container ("dexdata0" marker @ 0x4454)
│                         └── Custom LZ-compressed stream -> Real DEX Base @ 0x5460
│                             ├── string_ids [0x54D0..] (SM4 encrypted, entropy ~7.998)
│                             ├── type_ids, proto_ids, field_ids, method_ids (Plaintext)
│                             ├── class_defs (Plaintext)
│                             └── code_item bytecodes (Plaintext Dalvik opcodes)
│
└── lib/armeabi/libDexHelper.so (Packed Native Loader)
    └── .init_proc -> sub_AFA84 -> sub_AF76C -> sub_AFBF0 (Custom LZ Decompressor)
        └── Output: 439,185-byte decrypted native module
            ├── ART Hooks: sub_362C (OpenCommon), sub_3074 (OpenMemory)
            ├── String Obfuscation: sub_12584 (c - (i%3 + 1))
            └── Crypto Tables: Standard SM4 S-box @ 0x647B4, CK @ 0x64734, FK @ 0x87BC
```

---

## Technical Pipeline & Mechanics

### 1. libDexHelper.so Decryption via Unicorn Emulation
`libDexHelper.so` uses an internal unpacker triggered from `.init_proc`. Rather than running dynamic analysis under an ARM/x86 translation layer (which segfaults when hooking ART runtime internals), we emulate the unpacker routine statically using Unicorn Engine:
- **Loader descriptor**: Struct located at offset `0xAFE10` (`src=0x212E0`, `comp_len=0x3F0B8`, `decomp_len=0x6B391`, `xor_key=0`).
- **Decompression**: Executed through `sub_AFBF0` into an emulated memory buffer.
- **Relocation**: Emulates `sub_AF618` to fix internal jump and pointer tables.
- **Artifact**: Dumps a raw 439,185-byte ELF payload (`libDexHelper.dec.bin`). Injecting a minimal synthetic ELF header allows standard IDA Pro / Ghidra disassemblers to identify ~2,324 subroutines.

### 2. Container Demuxing (`dexdata0`)
The main `classes.dex` embeds the real payload after the stub:
- `0x4400`: Container header (total payload lengths, segment tables).
- `0x4454`: Magic ASCII marker `dexdata0`.
- `0x4460`: Compressed stream. Decompression yields a multi-DEX memory image containing both primary application classes (`dex1`) and bundled SDK frameworks (`dex2`, e.g. MDM management layers).

### 3. Bytecode vs String-Table Isolation
Inspection of `dex2` reveals SecNeo's selective encryption model:
- `code_item` Dalvik bytecode structures are entirely plaintext (`const-string`, `invoke-virtual`, `iget`, `iput` etc.).
- All intermediate indexes (`type_ids`, `proto_ids`, `method_ids`, `class_defs`) remain plaintext.
- The string payload storage (`string_data_item` pool) is stored sequentially in plaintext.
- **Only** the array of 32-bit offsets in `string_ids` (`[0x8985F0..0x8B8000)`, 32,388 items, 129,552 bytes) is encrypted via SM4 in 16-byte blocks.

### 4. string_ids Reconstruction (Static Pool-Order Approximation)
The SM4 key is derived dynamically at runtime through ART runtime container references (`DexFileContainer` vtable at BSS `0x6EE2C`). Without executing ART on-device, the string table can be recovered statically with **>95% accuracy** using structural invariants:
1. **Low-Index Pool Invariant**: In Dalvik DEX construction, URLs, network endpoints, and method names written during compilation appear sequentially in the string data pool. Known anchors verify that pool order directly matches index order for low and mid indexes:
   - `idx 1909` -> `pool[1909]` = `"/mdm/dev/loginInitV3"` (exact match)
   - `idx 1934` -> `pool[1934]` = `"/mdm/loginInitV3"` (exact match)
   - `idx 1935` -> `pool[1935]` = `"/mdm/loginInitV3_pre"` (exact match)
2. **Type-Constraint Optimization**: Validating reconstructed tables against `type_ids` descriptors achieves **95.6% validity** across the entire 32,388-string index space, fully recovering API endpoints, class member names, and execution graphs without executing cryptographic routines.

---

## Directory Structure

```
.
├── docs/
│   ├── ARCHITECTURE.md          # In-depth technical breakdown of SecNeo internals
│   ├── SCRIPTS-REFERENCE.md     # Command-line usage for analysis utilities
│   ├── 00-OVERVIEW.md           # Master summary of fleet analysis (85 targets)
│   ├── 01-FINAL-REPORT.md       # Stage report: Static vs dynamic trade-offs
│   ├── 02-STATIC-UNPACK.md      # DEX container & encryption entropy analysis
│   ├── 03-LIBDEXHELPER-UNPACK.md# Stage-2 native unpacker reversal details
│   ├── 04-OPENCOMMON-REVERSED.md# ART OpenCommon hook disassembly and analysis
│   ├── 05-REA-WIRING.md         # IDA Pro / REA toolchain setup
│   ├── 06-DEXDATA0-REPORT.md    # Container offset maps and segment layout
│   ├── 07-DEX2-FAST-REPORT.md   # Structural validation of decrypted bytecode
│   ├── 08-DEX2-POOLSORT-REPORT.md # Pool-order static string recovery methodology
│   └── 09-BATCH-RESULT.md       # Fleet consistency audit across 47 .so targets
├── scripts/
│   ├── static_extract.py        # Surface triage & container boundary extractor
│   ├── dex_rebuild.py           # Container payload DEX header rebuilder
│   ├── recover_secneo_dex.py    # Automated DEX extraction from APK classes.dex
│   ├── batch_unpack_dexhelper.py# Batch processor for libDexHelper.so instances
│   ├── unicorn/
│   │   ├── unicorn_bootstrap.py            # Unicorn ARM emulator setup
│   │   ├── unicorn_decompress_dexhelper.py # Emulated self-extraction engine
│   │   └── unicorn_decompress_dexdata.py   # Container stream decompressor
│   ├── dex2-pipeline/
│   │   ├── dex2_step1_verify.py      # Table boundary validator
│   │   ├── dex2_step2_boundary.py    # Section boundary discovery
│   │   ├── dex2_step3_classdefs.py   # class_def walker
│   │   ├── dex2_step4_chain.py       # ID table chain verification
│   │   ├── dex2_step5_relocate.py    # File offset relocation calculator
│   │   ├── dex2_step6_conststring.py # const-string opcode scanner
│   │   ├── dex2_step7_logininit.py   # Target method extractor
│   │   ├── dex2_step8_codeitems.py   # code_item table parser (21,790 items)
│   │   ├── dex2_step9_decode.py      # Dalvik instruction disassembler
│   │   ├── dex2_step10_strmap.py     # String index reference mapper
│   │   ├── rebuild_dex2_stringids.py # Assembly script for patched DEX
│   │   └── walk_pool2.py             # MUTF-8 string pool walker
│   ├── analysis/
│   │   ├── dump_dex_class.py         # Custom parser bypassing truncated map_list
│   │   ├── find_str_refs.py          # Cross-reference scanner for string indices
│   │   ├── fix_dex_ann.py            # Annotation directory offset sanitizer
│   │   ├── keysearch.py              # SM4 128-bit key search / brute-force tool
│   │   └── parse_encryptutil.py      # AST extractor for EncryptUtil signatures
│   └── frida/
│       ├── frida_dexdump_manual.py   # In-memory memory dumper (ARM device only)
│       └── frida_stringids_dump.js   # Dynamic string_ids interceptor
├── reversed/                         # Decompiled C modules (Hex-Rays / IDA Pro)
│   ├── hook_sub_362c.c               # Hook for art::DexFileLoader::OpenCommon
│   ├── hook_sub_3074.c               # Hook for art::DexFile::OpenMemory
│   ├── JNI_OnLoad_sub_3CB4.c         # JNI registration and cache-file staging
│   ├── af76c.c                       # Loader bootstrap stage 3
│   ├── afbf0.c                       # Custom LZ decompression algorithm
│   └── af618.c                       # Native ELF relocation processor
└── tools/
    └── sm4.py                        # SM4 implementation initialized with binary S-box
```

---

## Requirements & Environment

- **Python 3.10+**
- `unicorn >= 2.0.0` (required for native emulation)
- `pycryptodome >= 3.19.0` (required for SM4 verification tools)

```bash
pip install -r requirements.txt
```

---

## Execution Guide

### 1. Extract Container & Metadata
```bash
python scripts/static_extract.py target.apk
```

### 2. Emulate Native Loader Decompression
```bash
python scripts/unicorn/unicorn_decompress_dexhelper.py libDexHelper.so libDexHelper.dec.bin
```

### 3. Rebuild Main DEX Header & Sections
```bash
python scripts/dex_rebuild.py classes.dex unpacked_app.dex
```

### 4. Reconstruct Encrypted String Tables (dex2)
Run the verification and extraction stages:
```bash
cd scripts/dex2-pipeline
python dex2_step1_verify.py
python walk_pool2.py                  # Dumps pool2_walk.json
python rebuild_dex2_stringids.py      # Produces valid assembly DEX
```

---

## Operational Notes & Limitations

- **DEX Parsers & map_list**: Standard DEX disassemblers (e.g. older `androguard` versions) may fail on raw reconstructed SecNeo files due to zeroed-out or relocated `map_list` structures. Use `scripts/analysis/dump_dex_class.py` which computes table offsets directly from the DEX header fields.
- **Type Descriptor Drift**: Static pool-order approximation reconstructs URLs, fields, and method names with 100% precision. High-index type descriptors (`Lxxx/yyy;`) exhibit a ~396 slot index shift in the upper range (`idx > 11000`). If exact type resolution is mandatory for those classes, use the dynamic Frida hook script on a physical ARM device.

## License

MIT, Copyright (C) 2026 Evarentha. See [LICENSE](LICENSE).
