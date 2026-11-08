/*
 * Native Module Self-Relocation Routine
 *
 * Adjusts internal base address references across decrypted module segments.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file sub1ff68.c
 * @brief Adjusts internal base address references across decrypted module segments.
 *
 * Processes base relocations across the decrypted 439KB native core.
 */

int __fastcall sub_1FEA8(int a1, int a2)
{
  int v4; // r0
  int v5; // r10
  int i; // r5
  _DWORD *v7; // r1
  _DWORD *v8; // r2
  bool v9; // zf
  int v10; // r11
  int v11; // r4
  int v12; // r6
  int v14; // [sp+0h] [bp-20h]

  v4 = MEMORY[0x77188](a1); /*0x1febc*/
  if ( !v4 ) /*0x1fec0*/
    return 0; /*0x1ff66*/
  v5 = v4; /*0x1fec2*/
  for ( i = 0; i != 50; ++i ) /*0x1fec6*/
  {
    if ( *(_DWORD *)(0x727BC + 4 * i) == a1 ) /*0x1fed4*/
    {
      if ( !sub_4F4(a2, MEMORY[0x6EE6C], 5) || !sub_4F4(a2, MEMORY[0x6EE70], 10) ) /*0x1fef4*/
      {
        v7 = (_DWORD *)(v5 & 0xFFFFF000); /*0x1fefe*/
        do /*0x1ff0e*/
        {
          v8 = v7 - 1024; /*0x1ff04*/
          v9 = *v7 == 1179403647; /*0x1ff0a*/
          v7 -= 1024; /*0x1ff0c*/
        }
        while ( !v9 ); /*0x1ff0e*/
        if ( *((_BYTE *)v8 + 4106) != 1 ) /*0x1ff18*/
          return 0; /*0x1ff18*/
        v5 -= *(_DWORD *)(0x71D30 + 4 * i); /*0x1ff22*/
        if ( *(_BYTE *)(MEMORY[0x6EE5C] + 2) == 49 ) /*0x1ff30*/
        {
          v10 = 0; /*0x1ff34*/
          v11 = 0; /*0x1ff38*/
          v14 = *(_DWORD *)(0x76ED0 + 4 * i); /*0x1ff40*/
          while ( v11 < v14 ) /*0x1ff4c*/
          {
            v12 = *(_DWORD *)(0x76F98 + 4 * i); /*0x1ff4e*/
            if ( !sub_2A8(a2, *(_DWORD *)(v12 + v10)) ) /*0x1ff5c*/
              return sub_E00(v5, *(_DWORD *)(v12 + v10 + 4), MEMORY[0x6EE64], MEMORY[0x6EE60]); /*0x1ff8c*/
            v10 += 16; /*0x1ff5e*/
            ++v11; /*0x1ff62*/
          }
        }
      }
      return v5; /*0x1ff4c*/
    }
  }
  return v5; /*0x1ff70*/
}
