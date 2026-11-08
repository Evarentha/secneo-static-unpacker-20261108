# Technical Architecture: Bangcle SecNeo Unpacking

This document details the internal layout, execution model, cryptographic implementation, and reconstruction pipeline of the Bangcle SecNeo (`com.secneo.apkwrapper`) Android packer family.

---

## 1. Multi-Layer Packaging Model

SecNeo partitions Dalvik bytecode and native execution into four distinct stages:

```
+-----------------------------------------------------------------------------------+
| Stage 1: Dalvik Stub (classes.dex)                                               |
| - Standard Dalvik header, ~17 KB                                                  |
| - Package: com.secneo.apkwrapper (Classes: AW, H, etc.)                           |
| - Custom Application entry point intercepts Android framework initialization     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Stage 2: Embedded Container (classes.dex payload offset)                          |
| - Offset: 0x4400 (immediate successor to stub DEX data)                          |
| - Magic identifier: "dexdata0" @ offset 0x4454                                    |
| - Payload: Proprietary LZ-compressed stream containing real multi-DEX modules     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Stage 3: Self-Extracting Native Loader (libDexHelper.so)                          |
| - ARM ELF shared library (~619 KB) executed during JNI_OnLoad                     |
| - Entry point (.init_proc) dynamically unpacks payload into memory                |
| - Output: 439,185-byte decrypted native core module (PT_LOAD0 segment)            |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Stage 4: Runtime Hook Engine & Selective Cryptography                             |
| - Decrypted core hooks ART runtime internals:                                     |
|   * art::DexFileLoader::OpenCommon                                                |
|   * art::DexFile::OpenMemory                                                      |
| - Code items & class definitions remain PLAINTEXT in memory                       |
| - string_ids table is encrypted via SM4 block cipher                              |
+-----------------------------------------------------------------------------------+
```

---

## 2. Native Loader Unpacking (`libDexHelper.so`)

### 2.1 Bootstrapping Flow
Execution originates in `.init_proc` at file offset `0xAF184`:

```
.init_proc (0xAF184)
  │
  ├──> sub_AFA84():
  │      Allocates executable memory buffer (PROT_READ | PROT_WRITE | PROT_EXEC)
  │      Copies initial unpacker routine from .rodata
  │
  ├──> sub_AF76C(): Loader Dispatcher
  │      Reads unpacker parameter block from descriptor @ 0xAFE10:
  │        - Compressed payload offset: 0x212E0
  │        - Compressed length:         0x3F0B8 (258,232 bytes)
  │        - Decompressed length:       0x6B391 (439,185 bytes)
  │        - XOR cipher key:            0x00000000 (Plain compression)
  │
  ├──> sub_AFBF0(): Proprietary LZ Decompressor
  │      Decompresses the 258 KB payload into the RWX buffer.
  │      Offset check: 0x212E0 + 0x6B391 = 0x8C671 (matches PT_LOAD0 allocation)
  │
  └──> sub_AF618(): Runtime Relocation Linker
         Parses relocation arrays within the unpacked buffer.
         Patches function pointers and internal GOT structures:
           *(base + reloc_offset[i]) = target_address[i]
```

### 2.2 Unpacked Artifact Characteristics
- **Size**: Exactly 439,185 bytes.
- **Fleet Consistency**: A batch extraction across 47 unique APKs confirmed that 46 instances shared an identical SHA-256 digest (`32af49fd998fb91d293d4a631109a0a19543884784a96b9cf99f2a0882e3c230`).
- **Disassembly**: Injecting an ELF32 header (targeting `entry = 0x26A4`, `e_machine = EM_ARM`) allows disassembly of 2,324 distinct functions.

---

## 3. ART Hook Engine & Hook Targets

The core module operates primarily by intercepting the Dalvik/ART class-loading path before Dalvik verification triggers.

### 3.1 `art::DexFileLoader::OpenCommon` Hook (`sub_362C`)
`sub_362C` intercepts ART's centralized DEX initialization function:
```c
// Prototype reconstructed from disassembly
void* hook_OpenCommon(
    const uint8_t* base,
    size_t size,
    const std::string& location,
    uint32_t location_checksum,
    const void* oat_dex_file,
    bool verify,
    bool verify_checksum,
    std::string* error_msg,
    void* dex_file_container)
{
    // SecNeo intercepts location string, checks for internal tags
    // Allocates internal tracking adapter:
    void* container_adapter = malloc(4);
    *(uint32_t*)container_adapter = *(uint32_t*)(MEMORY[0x6EE2C]) + 8; // Internal vtable
    
    // Dispatches to real OpenCommon or native decrypter
    ...
}
```

### 3.2 `art::DexFile::OpenMemory` Hook (`sub_3074`)
Provides backwards compatibility for Android runtimes prior to Android 9.0 (API 28):
- Patches the entry point of `libart.so!_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_`.
- Overwrites the function prologue with a dynamic Thumb trampoline (`0x7718C`).

---

## 4. Cryptographic Analysis: SM4-Encrypted `string_ids`

SecNeo does **not** encrypt Dalvik bytecode instructions or class hierarchies. Dalvik opcodes remain fully intact in memory. Instead, it selectively protects the string offset index table.

### 4.1 SM4 Implementation Details
The native core carries standard implementation artifacts for China's national block cipher SM4 (GB/T 32907-2016):
- **S-Box Table**: Located at offset `0x647B4` (identical to standard 256-byte S-box).
- **Constant Keys (CK)**: Located at offset `0x64734` (32 system parameters).
- **Family Key (FK)**: Located at offset `0x87BC` (`0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC`).

Verification using test vector `Key = 0123456789abcdeffedcba9876543210`, `Plain = 0123456789abcdeffedcba9876543210`:
```
Encrypted Result: 681edf34d206965e86b3e94f536e4246 (Valid)
```

### 4.2 Target Ciphertext Scope
In secondary DEX modules (`dex2`, representing internal application frameworks):
- Offset range: `[0x8985F0, 0x8B8000)`
- Total size: `129,552 bytes`
- Entry count: `32,388 items * 4 bytes/offset`
- Shannon Entropy: `7.9986` (indicating block-cipher encryption across 16-byte alignment boundaries).

```
DEX Layout in Memory
+-----------------------+ 0x000000
| Header (Plaintext)    |
+-----------------------+ 0x000070
| string_ids (SM4 CT)   | <-- [0x8985F0..0x8B8000): 32,388 encrypted 32-bit offsets
+-----------------------+
| type_ids (Plaintext)  | <-- Consecutive ascending string indices
+-----------------------+
| proto_ids (Plaintext) |
+-----------------------+
| field_ids (Plaintext) |
+-----------------------+
| method_ids (Plaintext)|
+-----------------------+
| class_defs (Plaintext)|
+-----------------------+
| code_items (Plaintext)| <-- Dalvik bytecode: 21,790 validated executable methods
+-----------------------+
| string_data_item pool | <-- Sequentially stored MUTF-8 string literals (PLAINTEXT)
+-----------------------+
```

---

## 5. Offline Table Recovery: Pool-Order Approximation

Because the actual string payload data (`string_data_item` entries containing lengths and MUTF-8 bytes) is stored **unencrypted** in the string pool, we can reconstruct the mapping array without dynamic decryption.

### 5.1 Correlation Invariant
During Dalvik DEX compilation, toolchains (DX, D8) append string literals sequentially into the string data pool while establishing index pointers. In low-to-mid index regions (which encompass URI paths, method identifiers, and package prefixes), the sequential storage layout within the unencrypted string data pool preserves a near-identity mapping with the original string index table.

Empirical verification against known `const-string` bytecode cross-references confirms exact index-to-pool correspondence across early sequential blocks, allowing accurate reconstruction of core API routes, field descriptors, and method invocation targets prior to encountering type descriptor reordering.

### 5.2 Global Structural Consistency
Evaluating the reconstructed string table against the 5,149 strict descriptors in `type_ids` validates the sorting model:

| Ordering Approach | Type Descriptor Validity | Usability |
|---|---|---|
| Raw Pool Sequence | **95.6%** (4,925 / 5,149) | Recovers all endpoints, members, and control logic |
| Canonical UTF-16 Order | 87.5% (4,506 / 5,149) | High descriptor fragmentation |
| Canonical MUTF-8 Order | 87.5% (4,506 / 5,149) | High descriptor fragmentation |

---

## 6. Execution Failures under Emulation (ARM-on-x86 Architecture Barrier)

Attempts to unpack SecNeo dynamically using x86 Android emulators (e.g. Android 10/11 system images with `libndk_translation`) encounter a deterministic failure:
1. `libDexHelper.so` initializes inside the ARM translation container.
2. The loader attempts to install function hooks directly into process memory (`libart.so`).
3. Because the host process is native x86_64, `libart.so` contains x86_64 machine instructions.
4. The translated ARM module writes ARM-mode trampolines into x86_64 code segments, triggering an unhandled `SIGSEGV` in `libndk_translation.so`.

**Conclusion**: Native unpacking of SecNeo via instrumentation (Frida) strictly requires bare-metal ARM hardware. Offline static extraction via Unicorn emulation avoids this limitation entirely.
