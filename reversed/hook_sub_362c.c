/*
 * art::DexFileLoader::OpenCommon Hook Handler
 *
 * Decompiled implementation of SecNeo's primary ART DEX loading hook.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file hook_sub_362c.c
 * @brief Decompiled implementation of SecNeo's primary ART DEX loading hook.
 *
 * Intercepts OpenCommon in Android 9+ runtimes to redirect DEX loading.
 */

BOOL __fastcall sub_362C(int *a1)
{
  int v2; // r6
  int v3; // r11
  int v4; // r0
  void (__fastcall *v5)(_DWORD *, int, int, _DWORD, _DWORD, _BYTE *, int, _DWORD, _DWORD, _DWORD, _BYTE *, _DWORD **, _DWORD); // r9
  int v6; // r4
  int v7; // r6
  int v8; // r5
  int v9; // r4
  BOOL v10; // r4
  int *v12; // [sp+24h] [bp-94h]
  _DWORD *v13; // [sp+28h] [bp-90h]
  _DWORD *v14; // [sp+2Ch] [bp-8Ch] BYREF
  _BYTE v15[12]; // [sp+30h] [bp-88h] BYREF
  _BYTE v16[12]; // [sp+3Ch] [bp-7Ch] BYREF
  _BYTE v17[64]; // [sp+48h] [bp-70h] BYREF
  _DWORD v18[4]; // [sp+88h] [bp-30h] BYREF
  int v19; // [sp+98h] [bp-20h]

  v13 = (_DWORD *)MEMORY[0x6EE20]; /*0x363e*/
  v19 = *MEMORY[0x6EE20]; /*0x3642*/
  v2 = *MEMORY[0x7706C]; /*0x364a*/
  v3 = *(_DWORD *)(MEMORY[0x7706C] + 20); /*0x364c*/
  v4 = sub_1B8( /*0x3656*/
         0,
         "_ZN3art13DexFileLoader10OpenCommonEPKhjS2_jRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjP"
         "KNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE");
  if ( v2 > v3 ) /*0x365c*/
    v3 = v2; /*0x365e*/
  v5 = (void (__fastcall *)(_DWORD *, int, int, _DWORD, _DWORD, _BYTE *, int, _DWORD, _DWORD, _DWORD, _BYTE *, _DWORD **, _DWORD))v4; /*0x3660*/
  if ( !v4 ) /*0x3662*/
  {
    v5 = (void (__fastcall *)(_DWORD *, int, int, _DWORD, _DWORD, _BYTE *, int, _DWORD, _DWORD, _DWORD, _BYTE *, _DWORD **, _DWORD))sub_933C(*(_DWORD *)(MEMORY[0x7706C] + 32), "_ZN3art13DexFileLoader10OpenCommonEPKhjS2_jRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE"); /*0x3670*/
    if ( !v5 ) /*0x3674*/
      goto LABEL_12; /*0x3674*/
  }
  v6 = *a1; /*0x3676*/
  v12 = a1; /*0x367c*/
  v7 = *(_DWORD *)(*a1 + 32); /*0x3680*/
  sub_1A0(v16, "AnoymousDex"); /*0x3686*/
  v8 = *(_DWORD *)(v6 + 8); /*0x368e*/
  sub_3230(v15); /*0x3692*/
  v18[0] = 0; /*0x369c*/
  if ( v3 == 28 ) /*0x369e*/
  {
    v14 = (_DWORD *)sub_248(4); /*0x36a8*/
    *v14 = MEMORY[0x6EE2C] + 8; /*0x36b0*/
    v5(v18, v6, v7, 0, 0, v16, v8, 0, 0, 0, v15, &v14, 0); /*0x36d0*/
  }
  else
  {
    v5(v18, v6, v7, 0, 0, v16, v8, 0, 0, 0, v15, (_DWORD **)v17, 0); /*0x36f4*/
  }
  v9 = v18[0]; /*0x36f8*/
  v12[2] = v18[0]; /*0x36fa*/
  sub_1C4(v15); /*0x36fe*/
  sub_1C4(v16); /*0x3704*/
  v10 = v9 != 0; /*0x370a*/
  while ( *v13 != v19 ) /*0x3716*/
  {
    sub_158(*v13 - v19); /*0x3722*/
LABEL_12:
    v10 = 0; /*0x3726*/
  }
  return v10; /*0x3720*/
}
