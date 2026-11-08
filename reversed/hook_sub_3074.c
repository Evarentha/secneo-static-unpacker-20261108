/*
 * art::DexFile::OpenMemory Hook Handler
 *
 * Decompiled implementation of SecNeo's legacy ART DEX loading hook.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file hook_sub_3074.c
 * @brief Decompiled implementation of SecNeo's legacy ART DEX loading hook.
 *
 * Intercepts OpenMemory in Android 8 and earlier runtimes via Thumb trampolines.
 */

int __fastcall sub_3074(
        int a1,
        int (__fastcall *a2)(int, int, _BYTE *, _DWORD, _DWORD, _DWORD, _BYTE *),
        int a3,
        int a4)
{
  _DWORD *v8; // r10
  int (__fastcall *v9)(int, int, _BYTE *, _DWORD, _DWORD, _BYTE *); // r6
  int v10; // r0
  int (__fastcall *v11)(int, int, _BYTE *, _DWORD, _DWORD, _DWORD, _BYTE *); // r6
  _BYTE v13[12]; // [sp+Ch] [bp-4Ch] BYREF
  _BYTE v14[12]; // [sp+18h] [bp-40h] BYREF
  _BYTE v15[12]; // [sp+24h] [bp-34h] BYREF
  _BYTE v16[12]; // [sp+30h] [bp-28h] BYREF
  int v17; // [sp+3Ch] [bp-1Ch]

  v8 = (_DWORD *)MEMORY[0x6EE20]; /*0x308a*/
  v17 = *MEMORY[0x6EE20]; /*0x3092*/
  sub_1A0(v14, "Anonymous-DexFile"); /*0x309a*/
  sub_3230(v13); /*0x30a4*/
  if ( a1 == 22 ) /*0x30aa*/
  {
    if ( *(_DWORD *)(MEMORY[0x7706C] + 8) == 2 /*0x30e6*/
      && !sub_1B8(
            a2,
            "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemM"
            "apEPKNS_7OatFileEPS9_") )
    {
      a2 = (int (__fastcall *)(int, int, _BYTE *, _DWORD, _DWORD, _DWORD, _BYTE *))sub_1AC( /*0x3138*/
                                                                                     a2,
                                                                                     "_ZN3art7DexFile10OpenMemoryEPKhjRKN"
                                                                                     "St3__112basic_stringIcNS3_11char_tr"
                                                                                     "aitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPS9_");
      v10 = a2(a3, a4, v14, *(_DWORD *)(a3 + 8), 0, 0, v13); /*0x314c*/
    }
    else
    {
      a2 = (int (__fastcall *)(int, int, _BYTE *, _DWORD, _DWORD, _DWORD, _BYTE *))sub_1AC( /*0x30f2*/
                                                                                     a2,
                                                                                     "_ZN3art7DexFile10OpenMemoryEPKhjRKN"
                                                                                     "St3__112basic_stringIcNS3_11char_tr"
                                                                                     "aitsIcEENS3_9allocatorIcEEEEjPNS_6M"
                                                                                     "emMapEPKNS_7OatFileEPS9_");
      v10 = a2(a3, a4, v14, *(_DWORD *)(a3 + 8), 0, 0, v13); /*0x3106*/
    }
  }
  else
  {
    if ( a1 != 21 ) /*0x30ae*/
      goto LABEL_12; /*0x30ae*/
    v9 = (int (__fastcall *)(int, int, _BYTE *, _DWORD, _DWORD, _BYTE *))sub_1AC( /*0x30ba*/
                                                                           a2,
                                                                           "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112ba"
                                                                           "sic_stringIcNS3_11char_traitsIcEENS3_9allocat"
                                                                           "orIcEEEEjPNS_6MemMapEPS9_");
    if ( v9 ) /*0x30bc*/
    {
      v10 = v9(a3, a4, v14, *(_DWORD *)(a3 + 8), 0, v13); /*0x30cc*/
    }
    else
    {
      v11 = (int (__fastcall *)(int, int, _BYTE *, _DWORD, _DWORD, _DWORD, _BYTE *))sub_1AC( /*0x3114*/
                                                                                      a2,
                                                                                      "_ZN3art7DexFile10OpenMemoryEPKhjRK"
                                                                                      "NSt3__112basic_stringIcNS3_11char_"
                                                                                      "traitsIcEENS3_9allocatorIcEEEEjPNS"
                                                                                      "_6MemMapEPKNS_7OatFileEPS9_");
      if ( !v11 ) /*0x3116*/
        goto LABEL_15; /*0x3116*/
      v10 = v11(a3, a4, v14, *(_DWORD *)(a3 + 8), 0, 0, v13); /*0x312a*/
    }
  }
  a1 = v10; /*0x314e*/
LABEL_12:
  while ( 1 ) /*0x3152*/
  {
    sub_1C4(v13); /*0x3152*/
    sub_1C4(v14); /*0x3158*/
    if ( *v8 == v17 ) /*0x3164*/
      break; /*0x3164*/
    sub_158(*v8 - v17); /*0x3170*/
LABEL_15:
    sub_1A0(v16, "Anonymous-DexFile"); /*0x3174*/
    sub_3230(v15); /*0x3182*/
    a2 = (int (__fastcall *)(int, int, _BYTE *, _DWORD, _DWORD, _DWORD, _BYTE *))sub_1AC( /*0x3190*/
                                                                                   a2,
                                                                                   "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt"
                                                                                   "3__112basic_stringIcNS3_11char_traits"
                                                                                   "IcEENS3_9allocatorIcEEEEjPNS_6MemMapES2_PS9_");
    a1 = a2(a3, a4, v16, *(_DWORD *)(a3 + 8), 0, 0, v15); /*0x31a4*/
    sub_1C4(v15); /*0x31a8*/
    sub_1C4(v16); /*0x31ae*/
  }
  return a1; /*0x316e*/
}
