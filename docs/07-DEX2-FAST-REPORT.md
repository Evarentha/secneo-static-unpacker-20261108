# DEX2 快速判定报告（30 分钟窗口）

> 目标：判断 SecNeo `dexdata0` 载荷内第二套表（dex2 = MDM SDK）的 `code_item` 是否可解，并取 `/mdm/loginInitV3` 参数。
> 证据标注 `Observed / Inferred / Assumed`；未跑项标 `NOT RUN`。

---

## 0. 结论（先说结果）

| 问题 | 结论 | 证据强度 |
|---|---|---|
| dex2 的 `code_item` 是否加密？ | **不加密。可解。** 已建成 21,790 条经验证的 code_item 表，字节码全部可按 Dalvik 解码 | Observed |
| dex2 的 id 表是否加密？ | **不加密。** type/proto/field/method/class_defs 全为明文且首尾严格相接（相邻表 delta = 0） | Observed |
| 唯一加密的是哪一块？ | **只有 `string_ids`**：`[0x8985F0, 0x8B8000)` = 32,388 × 4 = **129,552 B**，H = 7.9986 | Observed |
| 能否拿到 `/mdm/loginInitV3` 的参数名？ | **暂不能**：`const-string` 的**索引**能读，但 `string_ids`（索引→字符串）被加密，索引无法映射到正确字符串 | Observed |
| 还缺什么？ | **只缺 129,552 B 的 `string_ids` 解密**（不是整套 dex，也不是 code） | Observed |

一句话：**前一版报告「code_item 与 string_ids 整体加密」的判断是错的 —— code 是明文，唯一缺口是 string_ids 表。**

---

## 1. 假设验证：加密边界到底在哪（任务 1）

### 1.1 熵与可打印率

| 区间 | 大小 | H | 零字节 | 判定 |
|---|---|---|---|---|
| dex1 明文 strpool `[0x1A4FD4,+32K)` | 32,768 | 5.3479 | 0.007 | 明文基线 |
| dex2 头部猜测 `[0x896F80,0x897FF0)` | 4,208 | 7.6098 | 0.029 | 混合（含 dex1 map_list 尾部） |
| **dex2 string_ids `[0x897FF0,0x8B8000)`** | 131,088 | **7.9986** | 0.004 | **密文** |
| dex2 type_ids `[0x8B8000,+16K)` | 16,384 | 4.4382 | 0.501 | 明文 |
| dex2 pool2 strpool `[0x961B68,+32K)` | 32,768 | 5.7055 | 0.015 | 明文 |

滑动窗（1KB/步 1KB，`[0x894000,0x8B8000)`）显示**唯一一次跃迁**：`0x897400` 起 H = 7.805 → 7.99，直到 `0x8B8000` 结束。即密文块 ≈ `[0x897580, 0x8B8000)`。

### 1.2 表是否可解析（决定性）

`type_ids @ 0x8B8000, n=5503`：
- 4 字节 string_idx `< 32388` 的比例 **5390/5503 = 0.9795**
- 前 20 项 = 7557,7558,7559,…,7576（连续递增，符合 type_ids 按 string_idx 排序的特征）
- 越界 113 项 + 最大 1,702,548 → 说明表**尾部/部分项**异常，但主体明文

`proto_ids @ 0x8BD5FC, n=6088`：shorty_idx 在范围内 **6088/6088 = 1.0000**，return_type **6088/6088 = 1.0000**
`field_ids @ 0x8CF35C, n=27201`：class / type / name 全部 **1.0000**
`method_ids @ 0x904564, n=30873`：class **1.0000**，proto **0.9932**，name **1.0000**

**表链首尾严格相接（相邻表 delta = 0）**：
```
type_ids  end = 0x8BD5FC  == proto @0x8BD5FC     delta 0
proto     end = 0x8CF35C  == field @0x8CF35C     delta 0
field     end = 0x904564  == method @0x904564    delta 0
method    end = 0x940A2C  == class_defs @0x940A2C delta 0
class_defs end= 0x961B4C  ~  pool2 @0x961B68      delta 28
```
⇒ **表本身不加密**（前版「表也加密」结论作废）。

### 1.3 修正：string_ids 的真实起点

`32388 × 4 = 0x1FA10`，故 **string_ids = `[0x8B8000-0x1FA10, 0x8B8000)` = `[0x8985F0, 0x8B8000)`**（前版写的 `0x897FF0` 偏了 0x600）。密文块起点 `0x897580` 与「header 0x70 + 插入块 0x1000 + string_ids」正好对齐：
`0x8B8000 - 0x1FA10 - 0x1000 - 0x70 = 0x897580`。

---

## 2. class_defs 与 data 段（任务 2）

`class_defs @ 0x940A2C, n=4233`（32 B/项）：`class_idx` 合法 **4233/4233**；`source_file_idx = 0xFFFFFFFF` 845 项（合法「无」）。

`class_data_off` 分布（Observed）：
- 去重 **4120** 个，0 值 113
- 范围 **`[0x406090, 0x444B34)`**，跨度 `0x3EAA4` = 260,772 B
- 相邻间隔：min 8 / median **39** / mean **62.3**；直方图 `≤8:7, ≤24:950, ≤64:2122, ≤256:944, >256:96`
- 这是**真实的 class_data 偏移集合**（密集、单调、均值 62 B/类），不是随机数

但 `0x406090` 起的内容**不是合法 class_data_item**：
```
0x406090: 02 01 00 0e 00 01 02 00 00 0e 78 2d 3c 87 00 01 00 0e 00 01 00 0e 00 01 00 0e ...
                                                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                          4 字节周期重复
```
按 `(static,instance,direct,virtual)` 解出 `2,1,0,14` 是合理的，但随后 encoded_field 出现 **diff=0 重复**（非法），且整段呈现 4 字节周期。逐项链式校验（item_end == next cdo）**exact 0/800、±3 仅 18/800**。

⇒ **偏移集是真的，字节内容不是标准 class_data_item 编码**（与 pool2 的「表明文、内容重排」是同一类处理）。

### 2.1 关于「method 第三个 uleb = code_items_scan 绝对索引」的复核

在你给的模型下，我用现有 `code_items_scan.json`（**22,720 项**，首项 `[0xA31CB0,[54,4,1,0,2818,4]]`）在 `0x406090` 起 500 个 class_data 上复跑：
- 绝对索引 < 22720 的合法率 **195/500 = 39.0%**（不是 96.1%）
- 链式密度：exact-end **11/4119**，±2 **78/4119**
- 解出的样例 `abs_idx = 0,1,0,1,14,...` 反复循环 → 起始解析即错位

⇒ 结论 `Assumed`：**你的 96.1% 很可能用的是另一个 class_data 基址**（或你那份 scan 有 36,847 项 / 不同过滤条件）。我这边 `0x406090` 不是正确的 class_data 起点。**需要你确认**：那 500 个 class_data 的基址是哪个？`code_items_scan` 的生成参数（过滤条件、是否含 try/catch、是否要求 4 字节对齐）？给我 grep 到你脚本里的起始常量即可，我立刻按同一口径复现。

---

## 3. code 确实可读（本报告的硬成果）

### 3.1 数据段定位

`[0xA2EEB8, ~0xCAEEB8)` 熵 3.9–5.7、可打印 0.28–0.40（与 dex1 明文基线一致，远离 7.99）。头部按结构解码完全成立：

```
0xA2EEB8: 03 00 00 00 | ee 00 e7 00 8d 00 | 00 00      → type_list size=3 {238,231,141}
0xA2EEC4: 03 00 00 00 | d0 02 42 0f 4e 0d | 00 00      → type_list size=3 {720,3906,3406}
          01 00 00 00 | 51 07 | 00 00                      → size=1 {1873}
```
所有 type_idx < 5503 ⇒ 明文 type_list。

### 3.2 用「合法 opcode 流 + 精确收尾」建立 code_item 表

校验条件：4 字节对齐 + `regs∈[1,255]` + `ins≤regs` + `outs≤63` + `tries≤16` + `debug_info_off<N` + **整段指令流每个 opcode 合法（剔除 0x3E–0x43/0x73/0x79/0x7A/0xE3–0xF9，并正确跳过 packed/sparse/fill-array payload）且恰好结束于 `insns_start + 2*insns_size`**。

结果：**21,790 条 code_item 通过**（分块扫描，每块 256 KB）：

| 块 | 通过数 |
|---|---|
| 0xA2EEB8–0xAEEB8 | 216 |
| 0xAEEB8–0xB2EEB8 | 762 |
| 0xB6EEB8–0xBAEEB8 | 1,592 |
| 0xC2EEB8–0xC6EEB8 | 3,162 |
| 0xC6EEB8–0xCAEEB8 | 2,213 |
| 合计 | **21,790** |

产物：`unpack/out/dex2_code_items.json`（sha256 `34557cda…`）。

### 3.3 `/mdm/loginInitV3` 调用点（Observed）

`const-string` 扫描（0x1A 21c / 0x1B 31c，索引 < 32388）：

| 字符串 | 索引 | 命中位置 |
|---|---|---|
| `/mdm/loginInitV3` | **0x078E = 1934** | `0xAF2330`, `0xAF462C` |
| `/mdm/dev/loginInitV3` | 0x0775 = 1909 | `0xAED810`, `0xAF23A0`, `0xAF469C` |
| `/mdm/loginInitV3_pre` | 0x078F = 1935 | `0xAF0034` |

**这些索引与 `pool2_mdm_urls.json` 的文件序索引完全一致（三个连续/邻近索引同时命中）——这是索引映射在该区间正确的独立证据。**

定位到的 code_item 与方法体（`0xAF2314`，regs=14 ins=7 outs=6 units=48，完整解码见 `unpack/out/dex2_login_methods.txt`）：

```
0xAF2324  22 06 c4 03        new-instance v6, <type 964>
0xAF2328  62 02 7d 04        sget-object  v7, <type964;->field 0x011A>
0xAF232C  1a 01 5a 17        const-string v1, <idx 0x175A = 5978>
0xAF2330  1a 03 8e 07        const-string v3, '/mdm/loginInitV3'   <<<<<
0xAF2334  12 04              const/4 v4, #0
0xAF2336  1a 05 e2 55        const-string v5, <idx 0x55E2 = 21986>
0xAF233A  07 60              move-object/from16 …
0xAF233C  76 06 55 12 00 00  invoke-direct/range {v6..v11}, <type964>.<init>
0xAF2342  62 00 7e 04        sget-object v0, <builder>
0xAF2346  1a 01 18 6c        const-string v1, <idx 0x6C18 = 27672>
0xAF234A  12 02              const/4 v2, #0
0xAF234C  6e 52 56 12 16 08  invoke-virtual {v2,v3,v1}, addOption(key,value)
0xAF2352  62 08 7e 04        sget-object v0, <builder>
0xAF2356  1a 00 ff 6f        const-string v0, <idx 0x6FFF = 28671>
0xAF235A  6e 52 56 12 06 89  addOption(...)
0xAF2360  62 08 7e 04
0xAF2364  1a 09 9a 75        const-string v9, <idx 0x759A = 30106>
0xAF2368  6e 52 56 12 96 8a  addOption(...)
0xAF236E  62 08 7e 04
0xAF2372  1a 09 27 78        const-string v9, <idx 0x7827 = 30759>
0xAF2376  6e 52 56 12 96 8b  addOption(...)
0xAF237C  6e 40 5a 12 67 dc  invoke-virtual …, <idx 0xDC67 = 56423? → 越界，需修正>
0xAF2382  0e 00              return-void
```

**结构层面已经完全可读**：`new-instance` → `<init>(v7, url, v4, v5)` → 连续 4 次 `addOption(key, value)`。四个 key 的**字符串索引是确定的**（27672 / 28671 / 30106 / 30759），只差索引→字符串。

三份近似副本（prod `0xAF2314` / prod2 `0xAF4610` / dev `0xAED7F4` / pre `0xAF0018`）常量集不同：
- prod：`v1 = idx 5978`，`v5 = idx 21986`
- prod2：`v1 = idx 5978`，`v5 = idx 0x08BC = 2236`
- dev：`v1 = idx 5965`，`v5 = idx 0x08B1 = 2225`
- 四个 key 索引在 prod/prod2 完全相同，dev 前两个不同

---

## 4. 唯一阻塞点：`string_ids` 是「索引→偏移」排列，且被加密

### 4.1 三条硬证据

1. **熵/结构**：`[0x8985F0,0x8B8000)` 共 129,552 B，H = **7.9986**，零字节率 0.004；相邻项异或高位字节为 0 的比例 **0.004**（明文单调偏移应 ≈ 1.0），加性差分 <0x1000 的比例 **0/20000**，8/16 字节块重复 **0**（无 ECB 结构）⇒ 正经流/分组密码，不是 XOR/加法混淆。
2. **索引语义不可省**：`const-string` 只给索引（如 1934），没有 `string_ids` 就无法把索引换成字符串。
3. **两种「猜测排列」都被否证**（见 4.2）。

### 4.2 用类继承关系做全局否证（Observed）

`class_defs` 中有 **2,435 个类的 `superclass_idx = 3673`**（这正是 `Ljava/lang/Object;`），其 `string_idx = 11624`。于是真值必须满足：`string_ids[11624]` = pool 中 `Ljava/lang/Object;` 的偏移。

| 假设的索引顺序 | 索引 11624 解析到的字符串 | `superclass == Ljava/lang/Object;` |
|---|---|---|
| pool 文件序 | `Ljavax/servlet/http/Cookie;` | **0 / 4233** |
| pool 排序序（UTF-16 code unit） | `Lkotlin/collections/CollectionsKt___CollectionsKt$elementAt$1;` | **0 / 4233** |

`Ljava/lang/Object;` 在 pool 文件序中的位置是 **11228**，而真值要求 **11624** → 漂移 **396**；索引 1934（`/mdm/loginInitV3`）的排序序位置是 1802 → 漂移 **132**。漂移随索引增长 ⇒ **不是恒等、也不是排序，而是被打乱的排列**（string_ids 就是这张排列表）。

⇒ `NOT RUN / 需要密钥`：`string_ids` 解密。

---

## 5. 产物

```
unpack/out/DEX2_FAST_REPORT.md            本报告
unpack/out/dex2_code_items.json           21,790 条验证通过的 code_item（sha256 34557cda…）
unpack/out/dex2_login_methods.txt         /mdm/loginInitV3 等 4 个方法的完整解码（141 行）
unpack/out/dex2_step1.log..step10.log     逐步证据日志
unpack/dex2_step1_verify.py               熵/可打印率/表解析
unpack/dex2_step2_boundary.py             滑窗熵 → 密文边界
unpack/dex2_step3_classdefs.py            class_defs / class_data_off 统计
unpack/dex2_step4_chain.py                class_data 链校验
unpack/dex2_step5_relocate.py             偏移重定位假设检验
unpack/dex2_step6_conststring.py          const-string 全量扫描
unpack/dex2_step7_logininit.py            调用点定位
unpack/dex2_step8_codeitems.py            code_item 验证扫描（可复用）
unpack/dex2_step9_decode.py               方法级反汇编
unpack/dex2_step10_strmap.py              索引→字符串映射假设检验
```

---

## 6. 下一步（按性价比排序）

**① 解 129,552 B 的 string_ids（唯一阻塞）**

需要 `libDexHelper` 中处理 `dexdata0` 记录、负责把 `string_ids` 还原的那个函数。已知：
- 文件偏移 `[0x8985F0, 0x8B8000)`，长度 129,552，明文值域必须落在 `[0x961B68, 0xA2EEB8)`；
- 密文无周期、无 ECB 块重复 ⇒ 流密码或 CBC；`IV/密钥` 不在模块常量表（历史 439,169 个 16B 窗口已排除）；
- 现成工件 `unpack/out/libDexHelper.dec.elf`（439,269 B）可直接进 IDA/r2 交叉引用：

```bash
timeout 120 r2 -A unpack/out/libDexHelper.dec.elf -q -c 'iz~dexdata; iz~string; izz~DexHelper; afl~[Dd]ecrypt'
timeout 120 r2 -A unpack/out/libDexHelper.dec.elf -q -c 'axt @ str.string_ids; pdf @ sym.*decrypt*'
```

**② 解密验证用 oracle（解出来立刻可判定对错，不用起 JADX）**

```python
# 判定：解出的 32,388 个 u4 必须
#  (a) 全部落在 [0x961B68, 0xA2EEB8) 且互不相同
#  (b) 与 pool2 的 32,388 个 item 偏移集合完全相等（集合比较，不看顺序）
#  (c) s(string_ids[i]) 非递减（dex 要求）
#  (d) 三条已知锚点：string_ids[1909] -> '/mdm/dev/loginInitV3'
#                    string_ids[1934] -> '/mdm/loginInitV3'
#                    string_ids[1935] -> '/mdm/loginInitV3_pre'
#                    string_ids[11624] -> 'Ljava/lang/Object;'   ← 最硬的锚点(2435 类共用)
```

(d) 的 `Ljava/lang/Object;` 锚点尤其好用：`string_ids[11624]` 必须指向 `0x961B68 + (11228 项的偏移)` —— **已知明文对**，可直接拿来试明文攻击/密钥恢复。

**③ 若你那份 96.1% 的 class_data 基址不同**：给我起始常量与 scan 参数，我按同一口径复现，然后按你的路径重建 `method_ids[].code_off` 并出 `app2.final.dex`。当前我这边 `0x406090` 口径只到 39%，链密度 11/4119，无法据此重建。

**④ 运行时旁路（最省力）**：`Frida` hook `DexHelper` 解出 dex 的那一刻，直接 dump 内存里已解密的 `string_ids`（32,388 个 u4），随后本地就能完成全部静态映射——不需要逆向密钥。
