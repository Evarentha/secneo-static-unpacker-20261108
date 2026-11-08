# 讯飞畅言 · 梆梆 SecNeo 加固 一揽子逆向 — 阶段总报告

> 本文汇总本轮从"域名测绘"到"梆梆加固纵深逆向"的全部可复现成果与当前边界。
> 环境：Windows + Node24 + IDA Pro 9.2 + JADX 1.5.6；REA(IDA/JADX MCP) 已接入 pi。

---

## 0. 靶标与资产
- 学生端 App 全量：`E:\Team\Project\日志\apk\6.0-1`（85 APK + STU zip），5.0 目录另一套。
- 核心包：`管控平台_v5.6.10.4.xkt.apk`（`com.iflytek.mdmservice`）+ `lib/armeabi/libDexHelper.so`。
- 壳型：**梆梆安全 SecNeo**（`com.secneo.apkwrapper.AW` + `libDexHelper.so` + `assets/meta-data/*`）。

## 1. 服务面测绘（Observed）
- `imdm.changyan.com` 终端管控 Web 台；`csmp.changyan.cn`/`csmp.ceshiservice.cn` 为设备 MDM 核心 API。
- 全量设备指令接口：`/mdm/dev/loginInitV3`、`/mdm/devOperationV4`、`/mdm/MDMuploadDevMediaV2`、
  `/mdm/dev/getDevStrategyListV3`、`/mdm/site/getLatestWOBSiteListV6` 等（见 `REPORT_MDM.md`）。
- `api.changyan.com`=EPAS 网关；`open.changyan.com`=畅言教育开放平台(appkey)。

## 2. APK / DEX 层
- 85 APK 全量清单+包名（`apk_full_inventory.txt`）。
- `classes.dex` 明文结构重建：**7578 类 / 62406 方法 / 64469 字段**（`unpack/out/管控平台.structural.dex`）。
- **唯一加密段 = `string_ids`（0x54d0，32740 项密文 / 后 30022 项明文）**；其余 id 表与字节码明文。

## 3. libDexHelper.so 二级脱壳（纯静态，Unicorn）
```
.init_proc(0xaf184) → sub_AFA84(mmap+copy) → sub_AF76C(loader) → sub_AFBF0(自研 LZ 解码器)
装载器结构@0xafe10: src=0x212e0 len=0x3f0b8 解压后=0x6b391 XORkey=0
Unicorn 调 sub_AFBF0 → 439,185 B 真实代码  =  0x212E0+0x6B391 = PT_LOAD0 精确大小
```
产物：`unpack/out/libDexHelper.dec.bin`；脚本：`unpack/unicorn_decompress_dexhelper.py`。
**批量**：47 个含该 .so 的包中 **46 个解出同一载荷**（sha256 `32af49fd…`）→ 跨 App 通用运行时模块。

## 4. 解壳模块逆向（REA+IDA/Hex-Rays）
- 合成 ELF 头后 IDA 从 253 → **2324 个函数**（`unpack/out/libDexHelper.dec.elf`）。
- **dex 加载 hook**：
  - `sub_362C` → `art::DexFileLoader::OpenCommon(dex,size,location="AnoymousDex",…)`
  - `sub_3074` → `art::DexFile::OpenMemory(dex,size,location="Anonymous-DexFile",…)`
- **`JNI_OnLoad`（`sub_3CB4`）**：注册 SecNeo native(`AW.hn/pn`,`H.d`)、拼 `<cache>/classes.{jar,dex,odex}`、
  探测 `libart.so/libdvm.so`、安装 Thumb 跳板到 `0x7718C/90/94`。
- **字符串混淆破解**：`sub_12584(s,n)`: `s[i] -= (i%3+1)`；实证 `buvfvv0kqgq1z → assets/info.y`。
- hook 收到的是**明文内存 dex** → 解密在 hook 上游。

## 5. 当前边界
- `.so` 侧已到"hook 收明文"层；**dex 缓冲的解密函数仍未钉死**（非 `sub_12584` 同族：
  对 `string_ids` 暴力测 sub/add/xor×(i%k+c0) 全非单调）。
- 无设备，动态 `frida-dexdump` 未跑。

## 6. 结论与下一步（二选一即可收官）
1. **动态一步**（最稳）：root 模拟器 `frida-dexdump -U -f com.iflytek.mdmservice` → 完整明文 dex（含 string_ids）。
2. **继续静态**：对 `sub_3CB4` 产出 dex 缓冲的分支做 `rea trace-native-values` 数据流，
   或对模块内"作用于 ≈9MB 大缓冲的循环"做模式定位（疑自研流密码）。

## 7. 产物索引
```
unpack/REA_WIRING.md                 # REA+IDA+JADX 接线文档
unpack/STATIC_UNPACK.md              # classes.dex string_ids 加密分析
unpack/LIBDEXHELPER_UNPACK.md        # .so 二级脱壳记录
unpack/OPENCOMMON_REVERSED.md        # OpenCommon/OpenMemory hook + 字符串还原
unpack/unicorn_decompress_dexhelper.py / batch_unpack_dexhelper.py
unpack/out/libDexHelper.dec.bin / .dec.elf
unpack/out/reversed/{hook_sub_362c.c, hook_sub_3074.c, JNI_OnLoad_sub_3CB4.c}
unpack/out/管控平台.structural.dex    # 结构有效 dex(7578 类)
REPORT_MDM.md / apk_full_inventory.txt / BATCH_RESULT.md
```

---

## 8. 动态尝试（AVD）结果 — 架构墙（Observed）
- 环境补齐：`D:\Android\Sdk` + cmdline-tools；装 `system-images;android-30;google_apis;x86_64`（自带
  `libndk_translation`，`abilist=x86_64,…,armeabi-v7a`）；建 AVD `rea30`；`adb root` 可用；
  部署 `frida-server 17.23.3 (android-x86_64)`。
- 目标 APK 安装成功，`primaryCpuAbi=armeabi-v7a`。
- 首次崩溃 `dlopen failed: library "libDexHelper-x86.so" not found`（SecNeo stub 按
  `getRuntimeAbi()` 在 x86 上加载 `DexHelper-x86`）；投放 ARM 库为该名后**加载成功**。
- 随后 **SIGSEGV 在 `libndk_translation.so`**：
  `#00 art::JNI<false>::ExceptionClear → #01 DoTrampoline_JNIEnv_ExceptionClear → #02 <翻译的 ARM libDexHelper>`。
- **根因**：梆梆 libDexHelper 主动 **hook ART 运行时**；模拟器 ART 是 x86_64，ARM 库经翻译 hook x86 ART
  → 跨翻译边界 JNIEnv/跳板崩坏。**架构级不兼容**。
- Android 官方模拟器在 x86 主机**不支持 arm64 镜像** → 无真正 ARM 环境。
- 结论：`frida-dexdump` 需**真 ARM 设备**（或 QEMU 全系统 ARM，重型）。

## 9. 静态边界（最终）
- 已解剖：外层自解压+自重定位引导器(`sub_AF76C/AF618/AF454`) → 439KB 运行时模块(ART hook + 缓存) 
  → dex 加载 hook(`OpenCommon`/`OpenMemory`) + JNI_OnLoad(`sub_3CB4`) + 短串还原(`sub_12584`)。
- 未离线还原：`string_ids`(32740 项) 的还原规则——它与 ART `DexFileContainer`(`0x6EE2C` 虚表) 绑定，
  且 hook 收到的已是明文 dex；模块的 helper 均为文件/整数/字符串工具（无密码循环、无密码常量）。
- 已排除：位置族变换、zlib、标准密码常量、短串还原同族。
