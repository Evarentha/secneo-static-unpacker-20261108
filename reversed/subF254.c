/*
 * SecNeo Runtime Check Routine sub_F254
 *
 * Environmental integrity verification and anti-debugging check routine.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file subF254.c
 * @brief Environmental integrity verification and anti-debugging check routine.
 *
 * Scans process memory maps and status files for attached debuggers.
 */

int __fastcall sub_F254(int a1, _DWORD *a2, int a3, int a4)
{
  int v4; // r4
  _DWORD *v8; // r10
  int v9; // r0
  int v10; // r5
  int v12; // r6
  _BYTE v13[20]; // [sp+14h] [bp-6Ch] BYREF
  int v14; // [sp+28h] [bp-58h]
  int v15; // [sp+30h] [bp-50h]
  int v16; // [sp+64h] [bp-1Ch]

  v8 = (_DWORD *)MEMORY[0x6EE20]; /*0xf268*/
  v16 = *MEMORY[0x6EE20]; /*0xf270*/
  v9 = sub_4A0(); /*0xf272*/
  if ( v9 ) /*0xf276*/
  {
    v4 = v9; /*0xf278*/
    if ( a3 ) /*0xf27a*/
    {
      v10 = 0; /*0xf282*/
      if ( !sub_4AC(v9, a3, 0) ) /*0xf288*/
        goto LABEL_9; /*0xf288*/
    }
    sub_4DC(v4); /*0xf28c*/
  }
  v10 = 0; /*0xf290*/
  while ( *v8 != v16 ) /*0xf29a*/
  {
    sub_158(*v8 - v16); /*0xf2a6*/
LABEL_9:
    if ( !sub_4B8(v4, v13, 0, 0, v10, v10, v10, v10) ) /*0xf2ba*/
    {
      v10 = 0; /*0xf2c4*/
      if ( !sub_4C4(v4, 0) ) /*0xf2c6*/
      {
        if ( a4 && v14 == a4 ) /*0xf2d6*/
          goto LABEL_17; /*0xf2d6*/
        v12 = v15; /*0xf2d8*/
        *a2 = v15; /*0xf2da*/
        v10 = sub_254(v12); /*0xf2e4*/
        if ( !v10 ) /*0xf2e6*/
        {
          sub_8CC(100000); /*0xf2ea*/
          v12 = v15; /*0xf2ee*/
          v10 = sub_254(v15); /*0xf2f6*/
        }
        if ( sub_4D0(v4, v10, v12) <= -1 ) /*0xf306*/
        {
          sub_290(v10); /*0xf30a*/
LABEL_17:
          v10 = 0; /*0xf30e*/
        }
      }
    }
    sub_4DC(v4); /*0xf310*/
  }
  return v10; /*0xf2a4*/
}
