/*
 * Runtime ELF Relocation Rebuilder
 *
 * Decompiled relocation loop applying pointer fixups to unpacked native memory.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file af618.c
 * @brief Decompiled relocation loop applying pointer fixups to unpacked native memory.
 *
 * Iterates relocation table entries to rebind internal function pointers.
 */

// positive sp value has been detected, the output may be wrong!
int __fastcall sub_AF618(_DWORD *a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
  int v12; // r0
  int v13; // r12
  _DWORD *v14; // lr
  _DWORD *v15; // r8
  int i; // r12
  int v17; // r1
  int v18; // r3
  int j; // r1
  int *v21; // [sp-4h] [bp-14h]

  v21 = (int *)((char *)&dword_110 + 1); /*0xaf644*/
  while ( v21 != (int *)((char *)&dword_44 + 2) ) /*0xaf664*/
  {
    if ( v21 != (int *)((char *)&dword_104 + 1) ) /*0xaf670*/
    {
      if ( v21 == (int *)((char *)&dword_110 + 1) ) /*0xaf678*/
      {
        v21 = &dword_44 + 2; /*0xaf6b0*/
      }
      else if ( v21 == (int *)((char *)&dword_14 + 1) ) /*0xaf680*/
      {
        v21 = (_DWORD *)(&stru_210 + 8); /*0xaf690*/
        if ( a8 > 3 ) /*0xaf6a0*/
          a8 = 214; /*0xaf6a0*/
      }
    }
  }
  v12 = ((int (__fastcall *)(_DWORD, unsigned int, int, int, _DWORD *, _DWORD, int))sub_AF350)( /*0xaf6e8*/
          0,
          (4 * a3 + 4095) & 0xFFFFF000,
          3,
          34,
          a1,
          0,
          30);
  v13 = 0; /*0xaf6ec*/
  v14 = a1; /*0xaf6f0*/
  while ( v13 != a3 ) /*0xaf6fc*/
  {
    *(_DWORD *)(v12 + 4 * v13) = *v14; /*0xaf700*/
    *v14++ = 0; /*0xaf704*/
    ++v13; /*0xaf708*/
  }
  v15 = &a1[a3]; /*0xaf710*/
  for ( i = 0; i != a3; ++i ) /*0xaf714*/
  {
    v17 = *(_DWORD *)(a2 + 4 * i); /*0xaf71c*/
    v18 = *(_DWORD *)(v12 + 4 * i); /*0xaf720*/
    *(_DWORD *)(v18 + a4) = v17; /*0xaf728*/
  }
  ((void (__fastcall *)(int, unsigned int))sub_AF2A0)(v12, (4 * a3 + 4095) & 0xFFFFF000); /*0xaf734*/
  for ( j = 0; j != a3; ++j ) /*0xaf738*/
    v15[j] = 0; /*0xaf744*/
  return ((int (__fastcall *)(int))sub_AF454)(a4); /*0xaf760*/
}
