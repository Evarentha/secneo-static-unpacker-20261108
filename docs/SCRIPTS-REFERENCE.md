# Scripts & Tooling Reference

This document provides operational specifications, inputs, outputs, and parameters for all analysis tools in the repository.

---

## 1. Top-Level Extraction Pipeline

### `scripts/static_extract.py`
Parses Android APK archives and Dalvik headers without execution. Locates embedded container offsets and unpacker descriptors.

```bash
python scripts/static_extract.py <path/to/target.apk>
```

**Output**:
- Package manifest metadata (`package`, `versionCode`, `applicationClass`).
- Stub DEX header layout (`string_ids_size`, `class_defs_size`, `map_off`).
- SecNeo container boundary (`container_offset`, `segment_count`, `payload_size`).

---

### `scripts/dex_rebuild.py`
Carves the primary application payload from a raw SecNeo `classes.dex` file and outputs an aligned DEX image.

```bash
python scripts/dex_rebuild.py <input_classes.dex> <output_unpacked.dex>
```

**Parameters**:
- `input_classes.dex`: Extracted `classes.dex` containing the `dexdata0` container marker.
- `output_unpacked.dex`: Target path for the reconstructed Dalvik image.

---

### `scripts/recover_secneo_dex.py`
Automated multi-stage script that wraps container parsing, payload decompression, and header fixing.

```bash
python scripts/recover_secneo_dex.py <input_classes.dex> <output_directory>
```

---

### `scripts/batch_unpack_dexhelper.py`
Scans a target directory for unpacked APK structures, locates `libDexHelper.so` instances, and executes the Unicorn-based decompressor on each instance.

```bash
python scripts/batch_unpack_dexhelper.py <search_directory> [--output-dir <dump_dir>]
```

---

## 2. Emulated Native Execution (`scripts/unicorn/`)

### `unicorn_decompress_dexhelper.py`
Emulates ARM execution of `libDexHelper.so` from `.init_proc` to extract the secondary native module.

```bash
python scripts/unicorn/unicorn_decompress_dexhelper.py <libDexHelper.so> <output_payload.bin>
```

**Internal Hook Targets**:
- Emulates `malloc`/`mmap` calls via an internal linear memory allocator.
- Halts execution when the program counter leaves `sub_AF618` (post-decompression relocation phase).
- Dumps the memory block at `0x212E0` with length `0x6B391` (439,185 bytes).

---

### `unicorn_decompress_dexdata.py`
Standalone decompressor that executes SecNeo's LZ algorithm on arbitrary `dexdata0` payload slices extracted from `classes.dex`.

```bash
python scripts/unicorn/unicorn_decompress_dexdata.py <raw_container.bin> <decompressed_output.bin>
```

---

## 3. DEX2 Reconstruction Pipeline (`scripts/dex2-pipeline/`)

These scripts operate on the raw memory dump of secondary application frameworks (`dex2`). Run these sequentially or reference their logic for customized unpacking.

| Stage | Script | Purpose |
|---|---|---|
| 01 | `dex2_step1_verify.py` | Validates Dalvik header magic and verifies table counts |
| 02 | `dex2_step2_boundary.py` | Computes relative and absolute offsets of item tables |
| 03 | `dex2_step3_classdefs.py` | Validates `class_def_item` structures and superclass inheritance |
| 04 | `dex2_step4_chain.py` | Verifies structural adjacency of `proto_ids`, `field_ids`, `method_ids` |
| 05 | `dex2_step5_relocate.py` | Calculates base-offset adjustments for fragmented sections |
| 06 | `dex2_step6_conststring.py` | Scans Dalvik opcodes for `const-string` and `const-string/jumbo` references |
| 07 | `dex2_step7_logininit.py` | Isolates method definitions for target API call chains (`loginInitV3`) |
| 08 | `dex2_step8_codeitems.py` | Validates all 21,790 `code_item` bytecode instances |
| 09 | `dex2_step9_decode.py` | Decodes register instructions and opcode byte streams |
| 10 | `dex2_step10_strmap.py` | Cross-references pool strings against decompiled invocation sites |

### Key Pipeline Tools:

#### `walk_pool2.py`
Iterates through the unencrypted string data pool, decoding MUTF-8 lengths and byte sequences. Emits `pool2_walk.json`.

```bash
python scripts/dex2-pipeline/walk_pool2.py <path/to/dex2_slice.bin> <output/pool2_walk.json>
```

#### `rebuild_dex2_stringids.py`
Assembles the complete DEX file. Replaces the SM4-encrypted `string_ids` segment with computed pool offsets, updates header metadata, and recalculates Adler32 and SHA-1 checksums.

```bash
python scripts/dex2-pipeline/rebuild_dex2_stringids.py \
    --base-dex <dex2_slice.bin> \
    --pool-map <pool2_walk.json> \
    --output <app2_reconstructed.dex>
```

---

## 4. Analysis & Parsing Utilities (`scripts/analysis/`)

### `dump_dex_class.py`
Lightweight DEX parser implemented in pure Python. Does not require `androguard`. Tolerates corrupt or truncated `map_list` sections created by packer stub manipulations.

```bash
python scripts/analysis/dump_dex_class.py <target.dex> [--filter <class_prefix>]
```

---

### `find_str_refs.py`
Scans a target DEX file for all `code_item` blocks referencing a specified string index.

```bash
python scripts/analysis/find_str_refs.py <target.dex> <string_index>
```

---

### `keysearch.py`
Performs an exhaustive sliding-window search across decrypted native binaries (`libDexHelper.dec.bin`) to identify possible 128-bit SM4 keys matching known ciphertext/plaintext blocks.

```bash
python scripts/analysis/keysearch.py <decrypted_module.bin> <ciphertext_block_hex> <plaintext_block_hex>
```

---

### `parse_encryptutil.py`
Extracts Dalvik bytecode and method signatures specifically for cryptography utility classes (e.g. `com.iflytek.edu.apm.base.network.EncryptUtil`).

```bash
python scripts/analysis/parse_encryptutil.py <reconstructed.dex>
```

---

## 5. Dynamic Device Scripts (`scripts/frida/`)

These utilities are intended for validation on physical ARM test devices (root required).

### `frida_dexdump_manual.py`
Attaches to the active application process and extracts all in-memory DEX files directly from ART's internal tracking lists.

```bash
python scripts/frida/frida_dexdump_manual.py -U -n com.iflytek.mdmservice -o ./dumps/
```

### `frida_stringids_dump.js`
Frida hook script. Intercepts the SecNeo native decryption handler to dump the decrypted `string_ids` buffer directly to disk before execution begins.

```bash
frida -U -f com.iflytek.mdmservice -l scripts/frida/frida_stringids_dump.js --no-pause
```
