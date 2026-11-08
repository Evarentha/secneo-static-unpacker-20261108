#!/usr/bin/env python3
#
# Frida In-Memory DEX Memory Dumper
#
# Extracts in-memory DEX files from running Android processes via Frida.
#
# Authors:
# worryzu <worryzu@evarentha.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: MIT

"""
Attaches to target Android processes on a physical ARM device to dump fully decrypted DEX memory ranges directly from ART runtime tracking lists.
"""

"""frida_dexdump_manual.py — 梆梆 SecNeo 定向内存脱壳 (需 root 设备)

用途: 当 frida-dexdump 被反 dump 拦住时, 主动在 libDexHelper 解密完成点
      枚举进程内所有合法 dex 并落地。
用法: python frida_dexdump_manual.py <package> [outdir]
前置: pip install frida frida-tools ; 设备已 root 且 frida-server 已运行
"""
import sys, os, time
import frida

# 在目标进程内: 扫描 /proc/self/maps 的 rw- 匿名段, 按 dex 魔数检索并按 header file_size 校验
JS = r"""
var OUT = [];
function isDex(p){
  try{ return p[0]==0x64 && p[1]==0x65 && p[2]==0x78 && p[3]==0x0a; }catch(e){ return false; }
}
function scan(){
  var ranges = Process.enumerateRanges('rw-');
  ranges.forEach(function(r){
    var size = r.size;
    if (size < 0x70 || size > 64*1024*1024) return;
    var base = ptr(r.base);
    var data;
    try{ data = base.readByteArray(Math.min(size, 64*1024*1024)); }catch(e){ return; }
    if (!data) return;
    var u8 = new Uint8Array(data);
    for (var i=0; i+112 < u8.length; i+=4){
      if (u8[i]==0x64 && u8[i+1]==0x65 && u8[i+2]==0x78 && u8[i+3]==0x0a){
        var fileSize = (u8[i+0x20])|(u8[i+0x21]<<8)|(u8[i+0x22]<<16)|(u8[i+0x23]<<24);
        if (fileSize > 0x70 && i + fileSize <= u8.length){
          var dex = u8.slice(i, i+fileSize);
          send({addr: base.add(i).toString(), size: fileSize}, data2buf(dex));
        }
      }
    }
  });
}
rpc.exports = { scan: scan };
function data2buf(a){ var b=new Uint8Array(a); return b.buffer; }
"""

def on_message(msg, data):
    if msg.get("type") == "send":
        addr = msg["payload"]["addr"]; size = msg["payload"]["size"]
        fn = os.path.join(OUT, f"dex_{addr.replace('0x','')}_{size}.dex")
        open(fn, "wb").write(data)
        print("[+] dumped", fn)

if __name__ == "__main__":
    pkg = sys.argv[1]
    OUT = sys.argv[2] if len(sys.argv) > 2 else "OUT_dex"
    os.makedirs(OUT, exist_ok=True)
    dev = frida.get_usb_device(timeout=10)
    print("[*] spawn", pkg)
    pid = dev.spawn([pkg])
    sess = dev.attach(pid)
    script = sess.create_script(JS)
    script.on("message", on_message)
    script.load()
    dev.resume(pid)
    print("[*] waiting for app to load native shell (libDexHelper)...")
    time.sleep(8)
    for round_ in range(5):
        print(f"[*] scan round {round_}")
        script.exports_sync.scan()
        time.sleep(3)
    print("[+] done ->", OUT)
