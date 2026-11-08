/*
 * SecNeo Internal Runtime Routine sub_13E64
 *
 * Internal helper routine handling string deobfuscation and state validation.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file sub13e64.c
 * @brief Internal helper routine handling string deobfuscation and state validation.
 *
 * Assists with memory decoding and runtime state tracking.
 */

void __fastcall __noreturn sub_13E64(int a1)
{
  const char *v2; // r6
  int v3; // r4
  int v4; // r0
  int v5; // r4
  int v6; // r0
  int v7; // r5
  unsigned int v8; // r4
  int v9; // r0
  _BYTE v10[512]; // [sp+0h] [bp-4B0h] BYREF
  _BYTE v11[512]; // [sp+200h] [bp-2B0h] BYREF
  char v12[16]; // [sp+400h] [bp-B0h] BYREF
  _BYTE v13[132]; // [sp+410h] [bp-A0h] BYREF
  int v14; // [sp+494h] [bp-1Ch] BYREF

  sub_B0(v13, 128); /*0x13e7a*/
  sub_284(v13, a1); /*0x13e82*/
  sub_290(a1); /*0x13e88*/
  sub_98(2); /*0x13e8e*/
  strcpy(v12, "buvfvv0kqgq1z"); /*0x13eac*/
  sub_12584(v12, 13); /*0x13eb0*/
  sub_B0(v11, 512); /*0x13ebe*/
  sub_B0(v10, 512); /*0x13eca*/
  v2 = (const char *)MEMORY[0x6EE24]; /*0x13ed8*/
  sub_BC(v10, "%s%s", MEMORY[0x6EE24], ".cache"); /*0x13ee2*/
  sub_BC(v11, "%s%s", v2, ".cache/info.y"); /*0x13ef0*/
  if ( sub_D4(v11, 0) ) /*0x13ef8*/
  {
    if ( sub_D4(v10, 0) ) /*0x13f02*/
      sub_3EC(v10, 511); /*0x13f0e*/
    v3 = *(_DWORD *)(MEMORY[0x7706C] + 580); /*0x13f1a*/
    if ( sub_D4(v11, 0) ) /*0x13f20*/
    {
      v4 = sub_F24C(v3, &v14, v12); /*0x13f30*/
      if ( v4 ) /*0x13f34*/
      {
        v5 = v4; /*0x13f36*/
        v6 = sub_1F4(v11, 578, 438); /*0x13f42*/
        if ( v6 >= 1 ) /*0x13f48*/
        {
          v7 = v6; /*0x13f50*/
          sub_200(); /*0x13f52*/
          sub_20C(v7); /*0x13f58*/
        }
        sub_290(v5); /*0x13f5e*/
      }
    }
  }
  v8 = 1; /*0x13f64*/
  while ( 1 ) /*0x13f68*/
  {
    ((void (__fastcall *)(_BYTE *))loc_13F9C)(v11); /*0x13f68*/
    if ( v8 < 0x64 ) /*0x13f6e*/
      ++v8; /*0x13f70*/
    v9 = sub_543A8(v8, 10); /*0x13f76*/
    sub_98(v9 + 3); /*0x13f7c*/
  }
}
