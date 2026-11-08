# libDexHelper 解壳后模块 — OpenCommon / dex 加载 hook 逆向

> 输入：`unpack/out/libDexHelper.dec.bin`（二级脱壳产物，439,185 B，跨 46 个包一致）
> 手段：合成 ELF 头 → REA(IDA Pro 9.2 + Hex-Rays) 分析
> 产物：`unpack/out/libDexHelper.dec.elf` + `unpack/out/reversed/*.c`

---

## 1. 合成 ELF 头（让 IDA 能分析）

解压产物是非独立映像（无 ELF 头），此前 IDA 只识别到 **253** 个函数。手工合成一个最小 ELF32：

```python
# ELF header: ET_DYN / EM_ARM(0x28) / entry=0x26a4(第一个函数序言)
h = 52B（e_ident + e_type=3,e_machine=0x28,e_entry=0x26a4,e_phoff=0x34,e_phnum=1）
ph = 32B（PT_LOAD off=0 vaddr=0 filesz=memsz=len(payload) flags=R|X align=0x1000）
open("libDexHelper.dec.elf","wb").write(h + ph + payload)
```

结果：IDA 解析出 **2324 个函数**（此前 253），Hex-Rays 可用。脚本片段见本文件末尾。

## 2. `sub_362C` —— `DexFileLoader::OpenCommon` hook（Observed）

`rea trace OpenCommon` 命中字符串 `0x5d313`，引用者 = **`sub_362C`**。

```c
BOOL sub_362C(int *a1) {
  v4 = sub_1B8(0, "_ZN3art13DexFileLoader10OpenCommonEPKhjS2_j...");           // dlsym(libart, OpenCommon)
  v5 = v4 ? v4 : sub_933C(*(MEMORY[0x7706C]+32), "...OpenCommon...");          // 备用 dlsym 句柄
  v6 = *a1;                                                                // 内存 dex 描述符
  v7 = *(*a1 + 32);                                                        // dex size
  sub_1A0(v16, "AnoymousDex");                                             // std::string location
  v8 = *(v6 + 8);                                                          // dex base
  if (v3 == 28 /*API28*/) {                                                // Android 9 分支
    v14 = sub_248(4); *v14 = MEMORY[0x6EE2C] + 8;
    v5(v18, v6, v7, 0,0, v16, v8, 0,0,0, v15, &v14, 0);                   // 调 OpenCommon
  } else {
    v5(v18, v6, v7, 0,0, v16, v8, 0,0,0, v15, v17, 0);
  }
  v12[2] = v18[0];                                                        // 保存 DexFile*
  return v10;
}
```
**结论**：`sub_362C` 把**已在内存中（已解密）**的 dex 以 location=`"AnoymousDex"` 交给 ART 的 `DexFileLoader::OpenCommon`。

## 3. `sub_3074` —— `DexFile::OpenMemory` hook（Observed）

`rea trace Anonymous-DexFile` 命中字符串 `0x5d2fc`，引用者 = **`sub_3074`**。

```c
int sub_3074(int a1, void *a2, int a3 /*dex base*/, int a4 /*dex size*/) {
  sub_1A0(v14, "Anonymous-DexFile");
  if (a1 == 22)        // ART 版本分支
    a2 = sub_1AC(a2, "_ZN3art7DexFile10OpenMemoryEPKhj...OatFileEPS9_"),
    v10 = a2(a3, a4, v14, *(a3+8), 0, 0, v13);          // OpenMemory(dex,size,"Anonymous-DexFile",...)
  else if (a1 == 21)
    ... 5 参数变体 ...
  return v10;
}
```
**结论**：另一条加载路径，location=`"Anonymous-DexFile"`，走 `art::DexFile::OpenMemory`。

## 4. `sub_3CB4` —— `JNI_OnLoad`（Observed，907 行）

`rea trace JNI_OnLoad` → 引用者 `sub_3CB4`。它：
- 注册 SecNeo 的 native（`com/secneo/apkwrapper/AW`、`H`，`sApp`，`getApplicationInfo`…）；
- 操作 APK 路径与缓存：`"classes.dex"` `"classes.jar"` `"classes.odex"` `".apk"` `".cache"` `"/sdcard/"`；
- 探测运行时：`"/system/lib/libart.so"` `"/system/lib/libdvm.so"` `"com.android.art"` `"com.google.android.art"` `"MATCH_APEX"`；
- 安装 hook：`MEMORY[0x6EE80](target, &loc_20214+1, 0x7718C)` 等（把 Thumb 桩指针写进 0x7718C/0x77190/0x77194 表）；
- 含混淆常量串：`"&g1gg1&g"` `"0ecth0bsm"` `"0stpf1&g1gg"` `"d1c2f0EF"`。

**结论**：`JNI_OnLoad` 负责定位 libart 的 `OpenCommon/OpenMemory` 并安装跳板；
`sub_362C`/`sub_3074` 是被调用的落地 hook。两者接收的都是**已解密**的内存 dex。

## 5. 解密点在何处（Inferred → 待验证）
`sub_362C`/`sub_3074` 的 `dex base/size` 由调用者（被 hook 的 ART 入口）给出，
即**解密发生在 hook 之前**。候选来源：
1. `sub_3CB4` 内的 APK→`classes.dex` 读取/变换路径（混淆常量 `d1c2f0EF` 等疑为 key/tag）；
2. 或 SecNeo 运行时在 `AW/H` 的 native 回调里先解出 dex 再触发加载。
下一步：对 `sub_3CB4` 里引用 `"classes.dex"` / `"d1c2f0EF"` 的分支做数据流跟踪（`rea trace-native-values`）。

## 6. 合成 ELF 脚本
```python
import struct
p=open("libDexHelper.dec.bin","rb").read()
h=bytearray(0x34); h[0:16]=b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
struct.pack_into("<HHIIIIIHHHHHH",h,16,3,0x28,1,0x26a4,0x34,0,0x05000000,0x34,0x20,1,0x28,0,0)
ph=bytearray(0x20); struct.pack_into("<8I",ph,0,1,0,0,0,len(p),len(p),5,0x1000)
open("libDexHelper.dec.elf","wb").write(bytes(h)+bytes(ph)+p)
```
分析：
```bash
export REA_ANALYSIS_PROVIDER=ida REA_IDA_MCP_CONFIG='C:\Users\worryzu\.rea\ida-mcp.json'
rea analyze libDexHelper.dec.elf --provider ida --format json      # -> 2324 funcs
rea trace   libDexHelper.dec.elf OpenCommon --provider ida        # -> string 0x5d313 <- sub_362C
rea decompile libDexHelper.dec.elf 0x362c --provider ida          # hook
```

## 7. 产物
```
unpack/out/libDexHelper.dec.elf                 # 合成 ELF（可分析）
unpack/out/reversed/hook_sub_362c.c             # OpenCommon hook
unpack/out/reversed/hook_sub_3074.c             # OpenMemory hook
unpack/out/reversed/JNI_OnLoad_sub_3CB4.c       # JNI_OnLoad 全文
```

---

## 8. 字符串混淆已破解（Observed）

模块内的短字符串用**位置相关逐字节减法**混淆：`sub_12584(s, n)`：

```c
for (i=0;i<n;i++) s[i] -= (i%3 + 1);   /* 即 s[i] += ~(i%3) */
```

实测还原：
```
b"buvfvv0kqgq1z"  -> b"assets/info.y"
b"d1c2f0EF"       -> b"c0z... " (16bit wide 形态，见 sub_3CB4 @0x40fc)
b"0ecth0bsm"      -> b".cache/..." (路径片段)
```
该还原器已固化为脚本片段（见下）。用同族位置变换暴力测试 APK `classes.dex` 的
加密 `string_ids`（0x54d0, 32740 项）—— **不适用**（sub/add/xor × (i%k+c0) 全部非单调），
说明 string_ids 用的是另一套密码。

## 9. 当前边界 / 下一步
- 已定位：`OpenCommon`/`OpenMemory` hook（`sub_362C`/`sub_3074`）、`JNI_OnLoad`（`sub_3CB4`）、
  APK 路径拼接（`…/classes.jar|classes.dex|classes.odex`）、cache 处理（`sub_13E64`）、字符串还原（`sub_12584`）。
- 未钉死：**内存 dex 的解密函数**（hook 收到的已是明文）。
  下一步：对 `sub_3CB4` 中产出 dex 缓冲的分支做 `rea trace-native-values`，
  或对模块内"作用于大缓冲区(≈9MB)的循环"做模式定位（疑似自研流密码）。
```python
def deobf(s):
    b=bytearray(s)
    for i in range(len(b)): b[i]=(b[i]-((i%3)+1))&0xff
    return bytes(b)
```
