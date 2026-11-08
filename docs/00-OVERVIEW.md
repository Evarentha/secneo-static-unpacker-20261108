# 讯飞畅言 · 梆梆 SecNeo 加固 一揽子逆向 — 总成果文档

> 一次性可复现记录。环境：Windows x64 + Node24 + REA 6.5.0 + IDA Pro 9.2(Hex-Rays) + JADX + Android SDK。
> 全部结论标注 `Observed / Inferred`；未跑步骤标 `NOT RUN`。

---

## 0. 一句话结论
`管控平台` 等讯飞学生端 APK 使用**梆梆安全 SecNeo** 加固。本轮已把
**「外层自解压+自重定位引导器 → 内嵌 439KB 运行时模块 → ART dex 加载 hook → 国密 SM4」**
四层全部拆到可读并落盘工装；唯一未离线还原的是与该运行时绑定的 **SM4 密钥**（文件内不存在）。
静态可得的全部情报（服务面、dex 结构、模块符号、hook、算法）均已交付。

---

## 1. 环境与工具（Observed）
| 组件 | 版本/路径 |
|---|---|
| OS | win32 x64 |
| Node / npm | 24.15.0 / 11.12.1 |
| REA | `rea-agents@6.5.0` → `%APPDATA%\npm\rea` |
| IDA Pro | 9.2 `D:\Program Files\IDA Professional 9.2` |
| ida-pro-mcp | 上游快照 `c133c385`（含 `idb_close`）`idalib-mcp.exe` |
| jadx-headless-mcp | 0.7.1 `C:\Users\worryzu\.rea\jadx\jadx-headless-mcp-0.7.1-all.jar` |
| JADX | 1.5.6 `D:\JADX` |
| Android SDK | `D:\Android\Sdk`（补装 cmdline-tools；镜像 android-30/33 google_apis x86_64；AVD `rea30` 含 ARM 翻译） |
| frida | 17.23.3 + frida-server(android-x86_64) |
| Python | 3.14（capstone / pyelftools / unicorn / frida / pycryptodome） |

---

## 2. 阶段一：服务面测绘（`REPORT_MDM.md`）
- `imdm.changyan.com` = 终端管控平台（Web）；`csmp.changyan.cn` / `csmp.ceshiservice.cn` = 设备 MDM 核心 API。
- 全量设备接口（Observed）：`/mdm/dev/loginInitV3`、`/mdm/dev/loginWayV3`、`/mdm/dev/insertDevInfoV3`、
  `/mdm/dev/getDevStrategyListV3`、`/mdm/devOperationV4`、`/mdm/MDMuploadDevMediaV2`、
  `/mdm/uploadViolationV4`、`/mdm/site/getLatestWOBSiteListV6`、`/csb-client/mdmApi/getDeployInfo` …
- `api.changyan.com`=EPAS 网关(`api gateway service from Epas.(1.15.2@208)`)；`open.changyan.com`=畅言教育开放平台(appkey)。
- Web 台 API：`/mdm/classroom/web/login|me|logout`、`/home/deviceStatus`、`/device/list|timeline|appUsage|netConnect|violationRecords|metricPull`。
- 前端硬编码 key `zve="RGqqDPAgUDhUrcFdj5fv7gmDyfMq1zdO"`；`new5.txt` 含 accessToken `0794a00d-…`。
- MDM 指令字典：`HiteVisionMdm/HwMdm/HarmonyMdm/IFlyTekTye100Mdm/MiaMdm/KrjMdm` 的
  `disableHome/disableUsb/turnOnAdb/silentInstall/resetFactory/…`。

## 3. 阶段二：APK / DEX（`STATIC_UNPACK.md`, `apk_full_inventory.txt`）
- 85 APK 全量清单+包名；壳型统一 `libDexHelper.so` + `assets/meta-data/*`，`application=com.secneo.apkwrapper.AW`。
- `classes.dex` 容器：`[stub dex 0x0-0x4448][count=1/size=0xcde014/"dexdata0"][载荷]`，尾部 `"fdex"`；真 dex `base=0x5460`。
- 结构重建：**7578 类 / 62406 方法 / 64469 字段**（`unpack/out/管控平台.structural.dex`）。
- **唯一密文段 = `string_ids`**（0x54d0，前 32740 项密文、后 30022 项明文）；其余 id 表/字节码明文。

## 4. 阶段三：REA 接线（`REA_WIRING.md`）
- REA 接入 pi（207 tools）；IDA headless（`idalib-mcp`）与 JADX（0.7.1 JAR）双引擎打通。
- 关键坑与解法：上游 `ida-pro-mcp 2.0.0` 缺 `idb_close`/`max_lines` → 换快照 `c133c385`；
  Windows 路径 JSON 必须 `json.dump` 转义；bash `MSYS_NO_PATHCONV=1`。

## 5. 阶段四：libDexHelper.so 二级脱壳（`LIBDEXHELPER_UNPACK.md`）
- 引导：`.init_proc(0xaf184) → sub_AFA84(mmap+copy) → sub_AF76C(loader) → sub_AFBF0(自研 LZ 解码器)`，
  内含明文串 `"__b_a_n_g_c_l_e__check1234567_"`（完整性校验）。
- 装载器结构 @0xafe10：`src=0x212e0` `压缩长=0x3f0b8` `解压后=0x6b391` `XORkey=0`。
- **Unicorn 静态解压**：`0x212E0 + 0x6B391 = 0x8C671` = PT_LOAD0 精确大小 → 解出 **439,185 B 模块**。
- 外层自修复：`sub_AF618`=运行期 ELF 重定位重建(`*(base+reloc[i])=targets[i]`)；`sub_AF454`=指针表修正；`sub_AF4E8`=读 `/proc/self/maps`(反调试)。
- 批量：47 个 `libDexHelper.so` 中 **46 个解出同一载荷**(sha256 `32af49fd…`) → 跨 App 通用运行时模块。

## 6. 阶段五：运行时模块逆向（`OPENCOMMON_REVERSED.md`）
- 合成 ELF 头（entry=0x26a4）→ IDA **253 → 2324 函数**。
- **dex 加载 hook**：`sub_362C` = `art::DexFileLoader::OpenCommon(dex,size,location="AnoymousDex",…)`；
  `sub_3074` = `art::DexFile::OpenMemory(dex,size,location="Anonymous-DexFile",…)`（按 ART 版本 21/22/28 选参数）。
- `JNI_OnLoad(sub_3CB4)`：注册 SecNeo native(`AW.hn/pn`,`H.d/gha/he/sha/sn`)、拼 `<cache>/classes.{jar,dex,odex}`、
  探测 `libart.so/libdvm.so`、安装 Thumb 跳板到 `0x7718C/90/94`；含混淆常量 `"d1c2f0EF"/"&g1gg1&g"/"0ecth0bsm"`。
- **字符串混淆还原**：`sub_12584(s,n)`: `s[i] -= (i%3+1)`；实证 `buvfvv0kqgq1z → assets/info.y`。
- 容器：`sub_362C` 内 `malloc(4); *p = MEMORY[0x6EE2C]+8;`（ART `DexFileContainer` 适配器，虚表在运行时 BSS）。
- `sub_1FEA8`：模块自重定位解析（扫 ELF 魔数 `0x464C457F`）；`sub_655D4`：自修改 trampoline。

## 7. 阶段六：国密 SM4（Observed，关键突破）
- 模块内含标准 **SM4** 常量：`S-box @0x647b4`、`CK @0x64734`、`FK @0x87bc`（全为标准值）。
- 用这些常量实现的 SM4 **匹配官方测试向量** `681edf34d206965e86b3e94f536e4246`。
- `string_ids` 头部 130960 B = 16×8185，熵 7.999、每列 256 值、无分组重复 → 与 SM4 分组加密吻合。
- S-box 之后 0x648b4 为二次编码查表（`X X Y Z` 模式），非标准逆 S-box。
- **密钥穷举全负**：模块内 439,169 个 16 字节窗口、109,793 个对齐常量、`sub_12584` 还原的 3,494 串片段、
  常见串/MD5/SHA256、APK `assets/meta-data/*` 与签名证书 → 均非密钥。
- 产物：`ld/sm4.py`（标准 SM4 keyexp/enc/dec/dec_ecb，用模块自带常量）。

## 8. 阶段七：动态尝试（AVD）— 架构墙（Observed）
- 补装 SDK cmdline-tools + `system-images;android-30;google_apis;x86_64`（自带 `libndk_translation`）；
  建 AVD `rea30`；`adb root` 可用；部署 `frida-server 17.23.3`。
- 崩溃1：`dlopen failed: library "libDexHelper-x86.so" not found`（stub 按 `getRuntimeAbi()` 在 x86 加载 `DexHelper-x86`）。
- 投放 ARM 库为该名 → 加载成功；崩溃2：**SIGSEGV 在 `libndk_translation.so`**
  （`art::JNI::ExceptionClear` ← `DoTrampoline_JNIEnv_ExceptionClear` ← 被翻译的 ARM libDexHelper）。
- 根因：梆梆 libDexHelper **主动 hook ART**；模拟器 ART 是 x86_64，ARM 库经翻译 hook x86 ART → 跨翻译边界崩坏。
- Android 官方模拟器在 x86 主机**不支持 arm64 镜像** → **`frida-dexdump` 需真 ARM 设备**。

---

## 9. 产物索引（全部绝对路径）

### 报告
```
mdm_apk/REPORT_MDM.md                # 服务面/MDM 测绘
mdm_apk/unpack/README.md             # 本文档（总成果）
mdm_apk/unpack/REA_WIRING.md         # REA+IDA+JADX 接线
mdm_apk/unpack/STATIC_UNPACK.md      # classes.dex string_ids 加密分析
mdm_apk/unpack/LIBDEXHELPER_UNPACK.md# .so 二级脱壳
mdm_apk/unpack/OPENCOMMON_REVERSED.md# OpenCommon/OpenMemory hook + 字符串还原
mdm_apk/unpack/FINAL_REPORT.md       # 阶段总报告
mdm_apk/apk_full_inventory.txt       # 85 APK 清单(包名/版本/壳/签名)
mdm_apk/apk_inventory.txt            # 关键 APK 组件/权限
mdm_apk/BATCH_RESULT.md              # 批量脱壳结果
mdm_apk/mdm_strings.txt              # 管控平台 dex 字符串库(113,308 条)
```

### 脚本
```
unpack/static_extract.py             # 免设备静态情报提取
unpack/dex_rebuild.py                # 自动解 base + 重建 dex 头
unpack/unicorn_bootstrap.py          # Unicorn 引导框架
unpack/unicorn_decompress_dexhelper.py# .so 二级脱壳(自测通过)
unpack/batch_unpack_dexhelper.py     # 批量(46/47 同构)
unpack/frida_dexdump_manual.py       # 有设备时的 frida 脱壳
ld/sm4.py                            # 标准 SM4(模块自带常量)
C:\Users\worryzu\AppData\Local\Temp\dexdump_attach.py  # 真机一键脱壳
```

### 核心二进制产物
```
unpack/out/管控平台.structural.dex    # 结构有效 dex(7578 类/62406 方法/64469 字段)
unpack/out/管控平台.rebuilt.dex       # 同上前一版
unpack/out/libDexHelper.dec.bin       # 二级脱壳产物(439,185 B 模块)
unpack/out/libDexHelper.dec.elf       # 合成 ELF(IDA 2324 函数)
unpack/out/reversed/hook_sub_362c.c   # OpenCommon hook
unpack/out/reversed/hook_sub_3074.c   # OpenMemory hook
unpack/out/reversed/JNI_OnLoad_sub_3CB4.c
ld/libDexHelper.unpacked.so           # 回填解壳后的 .so
ld/dec_payload.bin                    # = libDexHelper.dec.bin
ld/{af76c.c,afbf0.c,af618.c,s3cb4.c,sub1ff68.c,sub655d4.c,subF254.c,...}
```

---

## 10. 复现命令速查
```bash
# 服务面
curl -sk "https://imdm.changyan.com/mdm/classroom/web/me"
# APK 清单
python unpack/static_extract.py <apk>
# dex 结构重建
python unpack/dex_rebuild.py <classes.dex> out.dex
# .so 二级脱壳
python unpack/unicorn_decompress_dexhelper.py libDexHelper.so dec.bin
# 批量
python unpack/batch_unpack_dexhelper.py
# REA（IDA/JADX）
export REA_ANALYSIS_PROVIDER=ida REA_IDA_MCP_CONFIG='C:\Users\worryzu\.rea\ida-mcp.json'
rea analyze libDexHelper.unpacked.so --provider ida --format json
rea decompile libDexHelper.dec.elf 0x362c --provider ida --format json
rea inspect-android-package <apk> --format json
# 合成 ELF 让 IDA 分析解压模块
python -c "import struct;p=open('dec.bin','rb').read();h=bytearray(0x34);h[:16]=b'\x7fELF\x01\x01\x01\x00'+b'\x00'*8;struct.pack_into('<HHIIIIIHHHHHH',h,16,3,0x28,1,0x26a4,0x34,0,0x05000000,0x34,0x20,1,0x28,0,0);ph=bytearray(0x20);struct.pack_into('<8I',ph,0,1,0,0,0,len(p),len(p),5,0x1000);open('dec.elf','wb').write(bytes(h)+bytes(ph)+p)"
# 动态（需真机/root）
python dexdump_attach.py <outdir>     # frida 内存扫描取全量明文 dex
```

---

## 11. 未决 / 硬边界（NOT RUN）
- **SM4 密钥**：文件内不存在（全空间穷举+字符串还原均无）→ 运行时派生；纯静态无法离线取得。
- **string_ids 明文**：与 ART `DexFileContainer` 强耦合，非独立可爆破密文。
- **动态 frida-dexdump**：x86 模拟器无法承载"ARM 库 hook ARM ART"（架构墙）→ 需真 ARM root 设备或 QEMU 全系统 ARM。
- 外层引导段之外的自解压/自定位细节（`sub_655D4` 自修改 trampoline、0x648b4 二次编码表）仅定性，未逐字节还原。
```
状态: 静态四层(壳/加载器/运行时模块/SM4)已解剖完毕；唯一缺口为运行时 SM4 密钥。
```
