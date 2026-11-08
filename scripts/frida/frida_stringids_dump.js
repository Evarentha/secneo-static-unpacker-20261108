/*
 * Frida Dynamic string_ids Interceptor
 *
 * Hooks SecNeo decryption routines to intercept plaintext string_ids buffers.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file frida_stringids_dump.js
 * @brief Hooks SecNeo decryption routines to intercept plaintext string_ids buffers.
 *
 * Frida script that hooks the SecNeo runtime module decryption routines, intercepting the decrypted string_ids buffer in memory before execution.
 */

const TARGET_LEN = 0x1FA10;   // 129,552 = 32388 * 4
const MIN_LEN    = 0x1F000;   // tolerate a header-adjusted copy

let dumped = 0;

function plausible(u32) {
  // A decrypted entry must be an offset inside the dex2 string-data pool.
  return u32 >= 0x901B68 && u32 <= 0xA6EEB8;
}

function scoreRange(ptr, len) {
  const n = Math.min(64, (len / 4) | 0);
  let ok = 0;
  for (let i = 0; i < n; i++) {
    let v;
    try { v = ptr.add(i * 4).readU32(); } catch (e) { return 0; }
    if (plausible(v)) ok++;
  }
  return n === 0 ? 0 : ok / n;
}

function dump(ptr, len, why) {
  if (dumped > 0) return;
  const r = scoreRange(ptr, len);
  // Ciphertext scores ~0; decrypted offsets score high. Require a clear win.
  if (r < 0.9) return;
  const take = Math.min(len, TARGET_LEN);
  try {
    const f = new File("/data/local/tmp/string_ids.bin", "wb");
    f.write(ptr.readByteArray(take));
    f.flush(); f.close();
    const m = new File("/data/local/tmp/string_ids.meta.txt", "w");
    m.write(`why=${why}\nptr=${ptr}\nlen=${len}\ntake=${take}\nscore=${r}\n`);
    m.flush(); m.close();
    dumped++;
    console.log(`[+] dumped ${take} bytes from ${ptr} (${why}, score=${r.toFixed(2)})`);
  } catch (e) {
    console.log(`[-] write failed: ${e}`);
  }
}

function hookLib(name) {
  const mod = Process.findModuleByName(name);
  if (!mod) { console.log(`[!] module not loaded yet: ${name}`); return false; }
  console.log(`[*] ${name} base=${mod.base}`);

  // 1) memcpy / memmove: catch the copy of the freshly decrypted table.
  ["memcpy", "memmove"].forEach(sym => {
    const p = Module.findExportByName(null, sym);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter(args) {
        const len = args[2].toInt32();
        if (len >= MIN_LEN && len <= 0x20000) dump(args[1], len, `${sym} len=${len}`);
      }
    });
  });

  // 2) Scan the call out-params: many protectors write in place, so also
  //    poll the dexdata buffer ranges once the module is up.
  return true;
}

function pollScan() {
  // In-place decryption leaves no memcpy, so sweep RW ranges for a block whose
  // first 64 words all look like pool offsets. Bounded: 4 MB window, 4 KB step.
  const ranges = Process.enumerateRanges("rw-");
  for (const r of ranges) {
    if (r.size < TARGET_LEN) continue;
    const end = r.base.add(r.size - TARGET_LEN);
    for (let p = r.base; p.compare(end) < 0; p = p.add(0x1000)) {
      if (scoreRange(p, TARGET_LEN) >= 0.9) { dump(p, TARGET_LEN, "range-scan"); return; }
    }
  }
}

setTimeout(() => {
  const ok = hookLib("libDexHelper.so");
  // The protected dex usually loads within a few hundred ms of app start.
  const iv = setInterval(() => {
    if (dumped > 0) { clearInterval(iv); return; }
    pollScan();
  }, 1500);
  setTimeout(() => { clearInterval(iv); console.log(`[*] scan stop, dumped=${dumped}`); }, 60000);
  if (!ok) console.log("[!] libDexHelper.so missing — is the app fully started?");
}, 300);
