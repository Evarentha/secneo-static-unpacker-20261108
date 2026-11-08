# libDexHelper.so 二级脱壳（梆梆 SecNeo）— 纯静态记录

> 目标：`管控平台_v5.6.10.4.xkt.apk` 的 `lib/armeabi/libDexHelper.so`（619,453 B）
> 产物：`unpack/out/libDexHelper.dec.bin`（**439,185 B** 真实代码）
> 手段：REA(IDA Pro 9.2 + Hex-Rays) 定位 + Unicorn 模拟内嵌解压器（无设备、无动态）

---

## 1. 包装结构（Observed）

`libDexHelper.so` 外层是**壳体**：节表被裁到 4 项、`.dynamic` 只剩 `NEEDED/SONAME`，
ELF `e_entry=0`、无 `DT_INIT`，且 `0x20000–0x60000` 高熵（密文）。但 IDA 恢复出真实符号名
（`ADexFileContainer`/`POOL_*`/`hex_yy*`/`mutex_*`），执行入口在末段 `0xaf174`。

```
.init_proc (0xaf184)
  └─ sub_AFA84(0xafa84)      # mmap(rwx) + 拷贝压缩数据
  └─ sub_AF76C(0xaf76c)      # 装载器：解压 + 可选 XOR
       └─ sub_AFBD0(0xafbd0) # 包装
            └─ sub_AFBF0(0xafbf0)  # 自研 LZ 范围解码器
```
这些函数里含明文串 **`"__b_a_n_g_c_l_e__check1234567_"`**（梆梆完整性校验），
失败走 `sub_AF4E8`（读 `/proc/self/maps` 反调试）。

## 2. 装载器参数（vaddr `0xafe10` = 文件 `0x96e10`）

| 字段 | 值 | 含义 |
|---|---|---|
| a1[3] | `0x000212e0` | 压缩数据源（静态 vaddr） |
| a1[7] | `0x0006b391` | **解压后大小 = 439185** |
| a1[8] | `0x00000000` | **XOR 密钥（本例为 0）** |
| a1[9] | `0x000212e0` | 解压目标基址（= 源，就地） |
| a1[10] | `0x0003f0b8` | **压缩长度 = 258232** |
| a1[2] | `0x0003fd81` | 另一段长度 |

装载器逻辑（`sub_AF76C` 关键行）：
```c
sub_AFBD0(dst, src, a1[7], a1[10]);          // 解压
for (i=0;i<a1[8];i+=4) *(dst+i) ^= a1[8];    // 可选 XOR(密钥=0 → 空操作)
```

## 3. 静态解压（Unicorn）

`sub_AFBF0(src, srcLen, dst, &outLen)` 是自包含的范围解码器（LZMA 风格位流，`v7&0x7F`
归一化 + `2*v7+1`）。用 Unicorn 载入三段 PT_LOAD，直接调用：

```
r0=0x212e0(src) r1=0x3f0b8(len) r2=OUT r3=&outLen  ->  sub_AFBF0(0xafbf0)
```

实测：**`outLen = 0x6b391 = 439185`，与 a1[7] 完全一致**（验证正确）。

复现：
```bash
python unpack/unicorn_decompress_dexhelper.py ld/lib/armeabi/libDexHelper.so unpack/out/libDexHelper.dec.bin
# -> decompressed size = 0x6b391 (439185)
# -> ARM prologues: 443 | OpenCommon@381655 | Anonymous-DexFile@381608
```

## 4. 解压产物定性（Observed）

解压出的 439KB 是**梆梆 SecNeo 的 ART 运行时劫持模块**，含：
- `Anonymous-DexFile` / `AnoymousDex` —— 以匿名方式把解密后的 dex 交给 ART；
- `_ZN3art13DexFileLoader10OpenCommonE...`（×3）—— hook 的目标函数；
- `libdexfile.so` / `libdvm.so` / `/system/lib/libLLVM.so` / `dexposed` / `dexstuff_defineclass`；
- `JNI_OnLoad`（payload 内 `0x645b8` 处字符串）、`.dynstr`/`.dynsym`/`.data` 等节名残留。

无标准密码常量（AES-Sbox/MD5-T/SHA256-K 均未命中）→ dex 解密非 stock 算法，
或由该模块从内存中的密文流解密后走 `OpenCommon` 匿名加载。

## 5. 产物
```
unpack/out/libDexHelper.dec.bin                 # 二级脱壳产物（439,185 B 真实代码）
unpack/unicorn_decompress_dexhelper.py          # 可复现的静态解压脚本
```

## 6. 未跑 / 下一步
- 解压产物非独立 ELF（无 ELF 头），需以 raw/rebased 方式交给 IDA 继续分析（REA 的 IDA
  provider 不支持 `raw-binary`，可改用 Ghidra provider 或先合成 ELF 头）。
- 全量 dex 明文仍建议动态 `frida-dexdump` 一步收口；或继续逆向 ART hook 里的
  `OpenCommon` 调用点，定位 dex 密文来源与解密钥。
