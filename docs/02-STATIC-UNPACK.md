# 梆梆 SecNeo 静态脱壳 — 结构分析与重建（管控平台 / com.iflytek.mdmservice）

样本：`E:\Team\Project\日志\apk\6.0-1\管控平台_v5.6.10.4.xkt.apk`
产物：`管控平台/rebuilt.dex`（结构有效，7578 类 / 62406 方法 / 64469 字段）
方法：纯静态（无设备、无动态）

---

## 1. 壳型（Observed）
- `AndroidManifest` application = **`com.secneo.apkwrapper.AW`** → 梆梆安全 SecNeo
- 原生库：`lib/armeabi/libDexHelper.so`（符号 `prepare_vmdex`、`DexFileLoader::LoadV26/V28/V34/V34_BETA1`）
- 完整性数据：`assets/meta-data/{manifest.mf, rsa.pub, rsa.sig}`

## 2. 文件容器结构（Observed）
```
0x00000000 ┌─ 合法“桩”dex (magic dex\n035, 5 classes) ──────────┐
0x00004448 ├─ 容器头: [u32 count=1][u32 size=0xcde014][u32 namelen=8]["dexdata0"]┤
0x0000445d │  <payload>                                                        │
0x00ce2464 └─ 尾部: [u32 0x4448]["fdex"]  (指向桩末 + 魔数) ───────────────────┘
```
- 桩 dex 内 map_list(0x4378) 末项被伪造：`string_id size=0xcde014 off=0x8`（＝容器长度），用于欺骗工具。

## 3. 真实 dex（base = 0x5460）
由自引用 map 项 `map_list off=0x89716c` 反解得 **base = 0x5460**（`0x5460 + 0x89716c = 0x89C5CC` ＝实际 map 位置；`base+0x3d518 = 0x42978` ＝实测 type_ids 递增数组）。map_list 共 18 段：

| 段 | size | off(rel) |
|---|---|---|
| header | 1 | 0x0 |
| string_id | 62762 | 0x70 |
| type_id | 9354 | 0x3d518 |
| proto_id | 14517 | 0x46740 |
| field_id | 64469 | 0x70fbc |
| method_id | 62406 | 0xeee64 |
| class_def | 7578 | 0x168c94 |
| debug_info | 62762 | 0x1a3fd4 |
| type_list | 8183 | 0x3387d8 |
| annotations_directory | 1018 | 0x34ce4a |
| encoded_array | 10322 | 0x35b32a |
| class_data | 9987 | 0x38fbf8 |
| annotation_set | 266 | 0x3a8e5c |
| hiddenapi | 5976 | 0x3aa2fc |
| annotation | 41823 | 0x3e89ec |
| string_data | 51259 | 0x43f2c4 |
| code_item | 7336 | 0x813ee8 |
| map_list | 1 | 0x89716c |

各 id 表首尾相接自洽（string_id 末 = type_id 首 = 0x3d518；…；class_def 末 = data 首 = 0x1a3fd4）。

## 4. 加密边界（Observed）
- `type_ids / proto_ids / field_ids / method_ids / class_defs / code_item` + 字符串池数据 **均为明文**。
- **唯一加密段 = `string_ids`（0x54d0, 251048 字节）**：熵 7.381（AES/流密码级；明文偏移表应 ~5.5）。单字节 XOR / 字节翻转均不能使其恢复单调 → 非轻量混淆。
- 因 string_ids 密文，工具无法把“字符串下标→偏移”映射，导致反编译失败；运行时由 libDexHelper 解密。

## 5. 重建结果（Observed）
`dex_rebuild.py` 用 base=0x5460 + 上述 map 写入标准头并落盘 `rebuilt.dex`：
```
LOADED  classes=7578   methods=62406   fields=64469   strings=62762
```
- 结构 100% 正确（类/方法/字段数与 class_def/method_id/field_id 完全一致）。
- 字符串内容错乱（string_ids 密文所致）——这是唯一缺口。

## 5.1 string_ids 加密实测（Observed）
- 表位于 `base+0x70`，62762 项 × 4B = 251048B。
- **前 32740 项（0x54d0–0x25460）为密文**：熵 7.999，99.76% 的值 > 文件大小（非偏移）→ AES/流密码级。
- **后 30022 项（0x25460–0x42978）为明文偏移**：熵 6.191，首=0x2ab1eb 末=0x3387cf，指向**后缀共享池**（如 `eSet/sListener/SubMenu` 均为长名后缀），**非按内容排序** → 该表不是 dex 的排序 string_ids，而是壳内部索引。
- `type_ids`(4995–29907) 全部落于密文头；`method/field name_idx`(max 62153) 落于明文尾。
- 结论：**壳仅加密该索引表**，其余（id 表/class_def/code_item/字符串池）明文。

## 6. 完整静态脱壳的收口点
把 `rebuilt.dex` 变为可反编译，只差 `string_ids` 解密。两条静态路径：

1. **逆向 libDexHelper 解密例程**（推荐）：
   - 目标符号：`_Z13prepare_vmdexi`（prepare_vmdex）、`DexFileLoader::Load*`
   - 手段：`objdump -d lib/armeabi/libDexHelper.so` 或 r2 → 定位接收 `string_ids` 缓冲(0x54d0 区)与 map 的调用链
   - 关键：找到对 string_ids 段（长度 0x3D4A8）的解密函数与密钥来源

2. **从明文池重建 string_ids**：dex 规定 `string_ids` 按 MUTF-8 升序。可解析明文池、排序后重建。
   现状：池被打散（最长连续链仅 6741，全文件去重 82468 > 62762，含伪命中），需精确切分到恰好 62762 条方可对齐下标。

## 7. 复现
```bash
python dex_rebuild.py classes.dex rebuilt.dex     # 结构与 map 已内建
python -c "from androguard.core.dex import DEX; d=DEX(open('rebuilt.dex','rb').read()); print(len(d.get_classes()))"
objdump -d ld/lib/armeabi/libDexHelper.so | grep -A40 prepare_vmdex
```
