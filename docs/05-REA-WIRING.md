# REA 接线文档（pi ← REA MCP ← IDA Pro 9.2 + jadx-headless-mcp）

> 目标：让 pi 通过 MCP 直连 REA，REA 再驱动 **IDA Pro（headless/idalib）** 与 **jadx-headless-mcp**，
> 形成「二进制反汇编/反编译 + APK/DEX 语义分析」的一体化逆向工作台。
> 本文档为一次性可复现记录，实测环境见文末。

---

## 0. 环境基线（实测）

| 组件 | 版本 / 路径 | 备注 |
|---|---|---|
| OS | win32 x64 | REA `doctor` 识别 |
| Node.js | v24.15.0（>=22 必需） | `rea` 运行宿主 |
| npm | 11.12.1 | |
| Java | Temurin OpenJDK 21.0.10 | 跑 jadx-headless-mcp JAR |
| REA | `rea-agents@6.5.0`（npm 全局） | `C:\Users\worryzu\AppData\Roaming\npm\rea` |
| IDA Pro | 9.2 | `D:\Program Files\IDA Professional 9.2`（`ida.exe` / `idat.exe`） |
| ida-pro-mcp | 上游快照 `c133c385`（含 `idb_close`） | `D:\Python\Python314\Scripts\idalib-mcp.exe` |
| JADX | 1.5.6 GUI | `D:\JADX\jadx-gui-1.5.6-with-jre-win` |
| jadx-headless-mcp | **0.7.1** all-jar | `C:\Users\worryzu\.rea\jadx\jadx-headless-mcp-0.7.1-all.jar` |

---

## 1. 安装 REA 并接入 pi

```bash
# 1) 全局装 REA（含 CLI 与 MCP server）
npm install -g rea-agents@6.5.0
rea --version            # 6.5.0

# 2) 自检 MCP 目录（207 tools / 6 prompts / protocol 2025-11-25）
rea mcp doctor

# 3) 注册进 pi（用户级 ~/.pi/agent/mcp.json）
pi mcp add rea -- rea mcp
pi mcp list              # 期望: rea: connected, 207 tools
```

---

## 2. 接入 IDA Pro（REA 的 native 分析引擎）

REA 通过 `REA_IDA_MCP_CONFIG` 适配一个上游 IDA MCP。选 **headless（idalib 数据库监督器）** 模式，无需开 GUI。

### 2.1 关键坑：上游版本必须带 `idb_close`

REA 的 headless profile 按**实盘工具目录**校验 `idb_open` / `idb_list` / `idb_close`。

- 你机器上 pip 装的 `ida-pro-mcp 2.0.0` **缺 `idb_close`**（该工具在 `mrexodia/ida-pro-mcp` PR #495 之后才加入），
  且 `decompile` 不接受 `max_lines/offset` → REA 会 fail-closed。
- 解决：安装 REA 官方验证过的上游快照 **`c133c385`**（含真 `idb_close` 与 `max_lines`）：

```bash
cd /tmp && git clone https://github.com/mrexodia/ida-pro-mcp && cd ida-pro-mcp
git checkout c133c3853faa111a9b00ee615c013b720d0c4acd
python -m pip install .          # 覆盖已成 2.0.0（版本号相同，文件替换）
grep -n 'def idb_close' "$(python -c 'import ida_pro_mcp,os;print(os.path.dirname(ida_pro_mcp.__file__))')/idalib_supervisor.py"
```

> 备用：若不换上游，可写一个 monkeypatch 包装器给旧版补 `idb_close(database, save=False)` 并
> 使其返回值带 `owned`/`backend` 字段（REA 会校验）。文件见 `C:\Users\worryzu\.rea\idalib_mcp_patch.py`。

### 2.2 REA 的 IDA 注册文件

`C:\Users\worryzu\.rea\ida-mcp.json`
```json
{
  "command": "D:\\Python\\Python314\\Scripts\\idalib-mcp.exe",
  "args": ["--stdio", "--max-workers", "1"],
  "mode": "headless",
  "env": { "IDADIR": "D:\\Program Files\\IDA Professional 9.2" }
}
```

---

## 3. 接入 jadx-headless-mcp（REA 的 Android 分析引擎）

REA 只认 **`jadx-headless-mcp 0.7.1`** 的 all-jar，需自行下载（REA 不代为安装）。

```bash
mkdir -p "C:/Users/worryzu/.rea/jadx" && cd "C:/Users/worryzu/.rea/jadx"
curl -sL -o jadx-headless-mcp-0.7.1-all.jar \
  https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar
curl -sL -o sum.txt \
  https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp.sha256
sha256sum -c sum.txt      # 期望 6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75
```
> JAR 是 fat-jar（内建 jadx-core），无需另配 jadx；只要 `java` 在 PATH 上即可。

---

## 4. 注入环境变量到 pi 的 REA 入口

`C:\Users\worryzu\.pi\agent\mcp.json`（注意：JSON 里 Windows 路径必须双反斜杠转义）
```json
{
  "mcpServers": {
    "rea": {
      "command": "rea",
      "args": ["mcp"],
      "env": {
        "REA_ANALYSIS_PROVIDER": "ida",
        "REA_IDA_MCP_CONFIG": "C:\\Users\\worryzu\\.rea\\ida-mcp.json",
        "REA_JADX_MCP_JAR": "C:\\Users\\worryzu\\.rea\\jadx\\jadx-headless-mcp-0.7.1-all.jar"
      }
    }
  }
}
```

> ⚠️ 用 shell heredoc 直接写这个 JSON 极易把 `\\` 变成 `\`（非法转义），务必用 Python `json.dump` 写。
> 改完后在 pi 里 `/reload`（或重启 pi）。

---

## 5. 验证（Observed）

```bash
export REA_ANALYSIS_PROVIDER=ida
export REA_IDA_MCP_CONFIG='C:\Users\worryzu\.rea\ida-mcp.json'
export REA_JADX_MCP_JAR='C:\Users\worryzu\.rea\jadx\jadx-headless-mcp-0.7.1-all.jar'

# A) provider 健康
rea doctor
#    ida-registration  ok=true  "IDA MCP registration is valid…"
#    jadx              ok=true  "JADX MCP bridge JAR validated…"
#    provider report   jadx: configured=true available=true

# B) 原生二进制分析（IDA + Hex-Rays）
rea analyze   libDexHelper.so --provider ida --format json
#    → {"procedure_count":254,"string_count":1676}
rea decompile libDexHelper.so 0x2a696 --provider ida --format json
#    → void __fastcall ADexFileContainer::~ADexFileContainer(...) { ... }   # Hex-Rays 输出

# C) APK/DEX 语义分析（jadx-headless-mcp）
rea inspect-android-package 管控平台_v5.6.10.4.xkt.apk --format json
#    → {"engine":{"name":"jadx-headless-mcp","version":"0.7.1","artifact_sha256":"6e5eacf5…"},
#       "package_name":"com.iflytek.mdmservice","version_name":"5.6.10.4.xkt",
#       "min_sdk":"23","target_sdk":"23","class_count":…,"signature_verification":…}
```

---

## 6. 常用命令速查

```bash
# —— 原生（IDA provider）——
rea analyze      <bin> --provider ida --format json
rea search       <bin> "vmdex" --kind procedures --provider ida --format json
rea search       <bin> "pattern" --kind strings --mode regex --provider ida --format json
rea function     <bin> <name|0xaddr> --provider ida --format json      # 函数全档
rea decompile    <bin> <name|0xaddr> --provider ida --format json      # 伪代码
rea inspect-native-load-image <bin> --format json
rea trace-native-values <bin> ...            # 数据流/调用依赖
rea address-to-file-offset <bin> <addr>      # 地址→文件偏移

# —— Android（JADX provider）——
rea inspect-android-package   <apk> --format json
rea search-android-classes    <apk> <query> --format json
rea inspect-android-class     <apk> <class> --format json
rea inspect-android-method    <apk> <method> --format json
rea trace-android-references  <apk> <class|method> --format json

# —— 其它已就绪能力 ——
rea list-adb-devices / pull-adb-package / read-adb-logcat      # 有设备时
rea start-frida-session / load-frida-script                    # 有设备时
rea execute-rizin-command / inspect-with-objdump               # 备用反汇编
```

---

## 7. 故障排查

| 现象 | 原因 | 处置 |
|---|---|---|
| `ida-registration: Cannot read …ida-mcp.json` | JSON 非法转义（单反斜杠） | 用 Python `json.dump` 重写 |
| close 阶段 `unexpected parameters: ['save']` | 旧上游 `idb_close` 无 `save` | 换快照 `c133c385` 或用 patch 包装器 |
| close 报 `expected boolean … 'owned'` | `idb_close` 返回值缺会话字段 | 返回值带上 `to_list_dict()`（patch 已处理） |
| `decompile` 报 `unexpected parameters: ['offset','max_lines']` | 上游 `decompile` 过旧 | 换快照 `c133c385` |
| `jadx: Set REA_JADX_MCP_JAR …` | 未设 JAR 路径 | 设 `REA_JADX_MCP_JAR` 指向 0.7.1 all-jar |
| `cleanup_incomplete` 且残留 worker | headless worker 未回收 | worker 有 idle TTL（默认 600s）；`rea` 进程退出不影响它，按 upstream `idb_list` 清理 |

---

## 8. 本轮接线产物清单

```
C:\Users\worryzu\AppData\Roaming\npm\rea                       # REA CLI
C:\Users\worryzu\.pi\agent\mcp.json                            # pi ← REA(env: ida+jadx)
C:\Users\worryzu\.rea\ida-mcp.json                             # REA ← idalib-mcp(headless)
C:\Users\worryzu\.rea\idalib_mcp_patch.py                      # 备用 idb_close 包装器
C:\Users\worryzu\.rea\jadx\jadx-headless-mcp-0.7.1-all.jar     # JADX MCP 引擎
D:\Python\Python314\Lib\site-packages\ida_pro_mcp\             # 上游快照 c133c385(已装)
```
