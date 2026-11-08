# SecNeo `dexdata0` 容器静态还原 — 阶段报告

> 样本：`E:/Team/Project/日志/apk/6.0-1/管控平台_v5.6.10.4.xkt.apk` (`com.iflytek.mdmservice`)
> 结论标注 `Observed / Inferred`；未完成项标 `NOT RUN`。

---

## 1. 容器结构（Observed，全部来自 hexdump）

`classes.dex` = 13,509,736 B (0xCE2468)，sha256 `7e2ea8ad52065d82593a2084aac358c1a0889d8845075fffb7eba4088481d8e0`

```
0x00000 .. 0x043A0   合法 stub dex（magic dex\n035, 274 strings, 5 classes: com.secneo.apkwrapper.AW/H/a/AP/CP）
0x043A0 .. 0x04440   0xB0 对齐填充
0x04440  01 00 00 00  │ count = 1
0x04444  78 43 00 00  │ 0x4378 = stub dex 的 map_off
0x04448  01 00 00 00  │ 1
0x0444C  14 e0 cd 00  │ 0x00CDE014 = 记录总长 (16B 头 + 0xCDE000 数据 + 4B 尾)
0x04450  08 00 00 00  │ name_len = 8
0x04454  "dexdata0"   │ 容器名
0x0445C  e0 cd 00 00  │ data_size = 0xCDE000 = 13,492,224
0x04460 .. 0xCE2460   │ payload（13,492,224 B）
0xCE2460  48 44 00 00 66 64 65 78   │ 尾部标记 "fdex"
```
（题目给的 13,492,232 = 0xCDE008 含 name_len+name；实际数据区为 0xCDE000。）

### 1.1 payload 真实结构（Observed，关键突破）

payload **不是密文整体**，也**不是压缩流**。它是「真 dex + 一段 0x1000 插入块」：

| payload 区间 | 内容 | 状态 |
|---|---|---|
| `0x0000..0x0070` | 真 dex header | 密文 |
| `0x0070..0x1070` | **插入块 0x1000**（非 dex 结构，不被任何偏移引用） | 密文 |
| `0x1070..` | 真 dex 从原 0x70 起的内容（string_ids 起点） | 前 32,740 项密文，其后明文 |
| `0x21000..0x3E518` | string_ids 尾部（30,022 项） | 明文 |
| `0x3E518..` | type_ids / proto_ids / field_ids / method_ids / class_defs | 明文 |
| `0x1A4FD4..0x3397D7` | 字符串池（62,762 项，MUTF-8 排序） | 明文 |
| `~0x896F80..0x8B8000` | 第二段密文区（dex2 头部+string_ids，见 §3） | 密文 |

三条独立证据锁定「插入 0x1000」：
1. string_ids 表 = `[0x1070, 0x3E518)` → `(0x3E518-0x1070)/4 = 62,762` 项，与池子 62,762 项**完全相等**；
2. 密文分界 `0x21000` 对应 `(0x21000-0x1070)/4 = 32,740` 项（与历史分析一致）；
3. 明文段 30,022 个 string offset **全部** 满足 `value + 0x1000 == 池内某个 string_data_item 起点`（30,022/30,022）。
   例：`string_ids[32740]=0x2AB1EB → +0x1000 = 0x2AC1EB`（池内 "apm" 的 item 起点）。

**纠正**：先前把 string offset 直接当文件偏移解析失败，是因为
(a) string 长度是 **UTF-16 code unit** 而非字节数（中文字符串会错位），
(b) 存在 0x1000 位移。

---

## 2. 产物 1：`unpack/out/app.dec.dex`（标准 dex，已验证）

```
路径   C:/Users/worryzu/Desktop/cyzhkt111/mdm_apk/unpack/out/app.dec.dex
大小   13,488,240 B (0xCDD070，含追加 map_list)
sha256 d19028e5fc3c8a5bd063e27893c87099d30863db52409ac18a3211668b213257
magic  dex\n035\0   checksum/sha1 重算
```

表结构（全部实测）：

| 段 | offset | count |
|---|---|---|
| string_ids | 0x000070 | 62,762 |
| type_ids | 0x03D518 | 9,354 |
| proto_ids | 0x046740 | 14,517 |
| field_ids | 0x070FBC | 64,469 |
| method_ids | 0x0EFE64 | 62,406 |
| class_defs | 0x168C94 | 7,578 |
| data (字符串池起点) | 0x1A3FD4 | 11,767,852 |

闭合校验：`class_defs 结束(0x168C94+7578*32) == data_off(0x1A3FD4) == 字符串池起点`（Observed）。
map_list 原文被加密/缺失，追加了一个 9 项的合成 map_list（header/string/type/proto/field/method/class/string_data/map_list），否则 jadx 在 `readMapList` 处越界。

重建脚本：`unpack/recover_secneo_dex.py`（含全部常量与断言）

### 2.1 jadx 反编译（已执行）

```
D:/JADX/jadx-gui-1.5.6-with-jre-win/jre/bin/java.exe -Xmx6g \
  -cp D:/JADX/jadx-gui-1.5.6-with-jre-win/lib/jadx-gui-1.5.6-all.jar \
  jadx.cli.JadxCLI -d jadx_dec --no-res --no-debug-info --threads-count 8 unpack/out/app.dec.dex
```
结果：`processing 2586/2586`，`finished with errors, count: 36`，输出 4,231 个 .java。
类型描述符解析正常（`Landroid/accessibilityservice/AccessibilityServiceInfo;` …），证明 string_ids 重建正确。
产物目录：`mdm_apk/jadx_dec/sources/`（含 `com/iflytek/edu` 844 个类、`com/huawei/hms` 869 个类）。

---

## 3. 第二段载荷（MDM SDK）：定位到，但代码段加密

payload 内还存在第二套 id 表 + 第二个字符串池（pool2），它是 **MDM SDK dex**：

| 段（以 app.dec.dex 坐标） | 内容 | 状态 |
|---|---|---|
| 0x896F80..0x897FF0 | dex2 header + 0x1000 插入块（0x896F80 由 0x8B8000-0x1070-4*32388 反推，误差 ≤0x100） | 密文（H≈7.99） |
| 0x897FF0..0x8B8000 | dex2 string_ids（32,388 项 = 129,552 B） | 密文 |
| 0x8B8000.. | dex2 type_ids | 明文 |
| 0x8CF35C..0x904564 | field_ids（27,201） | 明文 |
| 0x904564..0x940A2C | method_ids（30,873） | 明文 |
| 0x940A2C..0x961B4C | class_defs（4,233） | 明文 |
| 0x961B68..0xA2EEB8 | dex2 字符串池（**32,388 项，与 string_ids 数一致**） | 明文 |

pool2 明文可读，已导出：
`/mdm` 系接口字符串 59 条（`unpack/out/pool2_mdm_urls.json`），含

```
1909  /mdm/dev/loginInitV3      ← 设备 API
1910  /mdm/dev/loginWayV3
1934  /mdm/loginInitV3          ← 题目目标
1935  /mdm/loginInitV3_pre
26011 "loginInit HttpDone" 26012 "loginInit onException：" 26013 "loginInit onFailed: "
26017 "loginInit：onSuccess: "
```
另有源文件名常量 `MDMLogin`(13166)、`MDMUrls`(13178)、`MDMConstants.java`(13160)、`MDMKeys`(13164)、`MDMNetwork`(13167)。
**注意**：`MDMUrls`/`MDMLogin` 是 **source_file_name 字符串**，不是类名；dex2 的 class_defs 中没有任何 `source_file_idx` 指向 13166/13178（已穷举 4,233 条 class_def，Observed）。

### 3.1 为什么拿不到参数（Observed）

* 全库扫描 `const-string` 到 pool2 常用串（`toString`=30834、`onCreate`=27053、`getDeviceId`=23030）→ **0 命中**；
  到 `/mdm/dev/loginInitV3`(1909) → **0 命中**。
  说明 dex2 的 `code_item` 字节码整体被加密（与 H≈7.99 的密文块吻合）。
* dex2 的 `class_data_off` / `params_off` 指向的字节并非合法 `class_data_item`（逐项验证失败），即数据段也被加密/重定位。
* 结论：**/mdm/loginInitV3 的参数名只能来自 dex2 解密后的字节码**，静态明文不可得。
  `NOT RUN`：dex2 解密（需要 SecNeo 运行期密钥；历史分析已证明模块内 439,169 个 16B 窗口 + 常量表均非密钥）。

---

## 4. 接口在线验证（已执行，Observed）

```
curl -s -X POST -H 'Content-Type: application/json' --data '{}' \
     https://imdm.changyan.com/mdm/loginInitV3
→ HTTP 200  {"status":"500","message":"参数校验失败","data":null}
curl -X GET 同地址 → HTTP 405，Allow: POST, OPTIONS
curl -X POST https://imdm.changyan.com/mdm/dev/loginInitV3 → HTTP 302（该路径是设备 API，主机不对）
curl -X POST https://csmp.changyan.cn/mdm/dev/loginInitV3 → 404 {"error_msg":"404 Route Not Found"}
curl -X POST https://api.changyan.com/mdm/loginInitV3 → 403 {"message":"[S-AUTH-APPID]校验失败!","statusCode":"SHD-0101"}
```

网关/鉴权头契约（来自 405/403 的 CORS 回包，Observed）：
```
Access-Control-Allow-Headers:
  x-requested-with, origin, content-type, accept, jwt, uid,
  x-token, x-key, x-sign, x-s-key, x-deviceId, tokens
```
参数探测矩阵（均返回同一句 `参数校验失败`，Observed）：
`{}` / `{"username"}` / `{"userName"}` / `{"account"}` / `{"loginName"}` / `{"devSn"}` / `{"deviceId"}` /
`{"phone"}` / 23 字段合并体 / form-urlencoded / 非法 JSON `{` / `[]` /
加 `x-deviceId`/`x-token`/`x-sign`/`x-key`/`x-s-key`/`uid`/`tokens`/`S-AUTH-APPID` 头
→ 全部 `{"status":"500","message":"参数校验失败"}`，说明校验发生在**结构化反序列化之前**（拦截器级，多为签名/渠道头校验），
无法用响应差分枚举字段名。

原始回包已落盘：`unpack/out/probe/GET.txt`、`unpack/out/probe/POST.txt`、`unpack/out/probe/big1.resp`。

---

## 5. 产物索引

```
unpack/out/app.dec.dex                 # 标准 dex（已 jadx 验证）d19028e5…
unpack/out/app.dec2.dex                # 第二套表的重建尝试（代码段密文，仅表/池有效）976468d4…
unpack/out/classes.orig.dex            # APK 原始 classes.dex
unpack/out/stub.dex                    # 0x0..0x43A0 stub dex
unpack/out/pool2_mdm_urls.json         # pool2 全量 /mdm 接口 + MDM* 邻域串
unpack/out/manifest.mf / rsa.pub / rsa.sig
jadx_dec/sources/                      # dex1 反编译结果（4,231 java / 2,586 类）
jadx_dec2/sources/                     # dex2 表结构可读但类体为空（证据）
unpack/recover_secneo_dex.py           # dex1 重建（含断言）
unpack/build_dex2.py                   # dex2 骨架重建
unpack/mutf8_walk.py                   # MUTF-8 正确的 string_data 游走器（关键工具）
unpack/out/probe/*                     # curl 证据
```

## 6. 下一步（二选一即可闭环拿参数）

1. **解 dex2**：两段密文区 `[0x898FF0,0x8B8000)`（129,552 B = 32,388×4，正好是 dex2 string_ids）与
   `[0x8BC000?,0x8BD000?]` 附近的 code 密文；已知明文 = dex2 header 前 8 字节 `dex\n035\0`，
   可直接用于 SM4-ECB/CBC 的密钥候选快速筛选（模块内 S-box@0x647b4 / CK@0x64734 / FK@0x87bc 已确认标准值）。
2. **动态**：真 ARM root 设备 + `frida-dexdump -U -f com.iflytek.mdmservice`（历史结论：x86 模拟器不可用）。
