/*
 * Stage-3 Native Loader Bootstrap
 *
 * Decompiled native loader reading unpacker parameters and dispatching decompression.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file af76c.c
 * @brief Decompiled native loader reading unpacker parameters and dispatching decompression.
 *
 * Parses descriptor block @ 0xAFE10 and orchestrates memory allocation.
 */

int __fastcall sub_AF76C(_DWORD *a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10)
{
  int v13; // r8
  int v14; // r7
  int v15; // r0
  bool v16; // zf
  _DWORD *v17; // r7
  int v18; // r11
  int v19; // r4
  unsigned int v20; // r6
  int v21; // r8
  int v22; // r10
  unsigned int k; // r0
  int i; // r3
  int v25; // r2
  unsigned int j; // r0
  unsigned int v27; // r7
  int v28; // r1
  _DWORD *v29; // r3
  int v30; // r6
  int v31; // r2
  unsigned int v32; // r11
  int v33; // t1
  int *v35; // [sp+14h] [bp-8h]

  v35 = (int *)((char *)&dword_110 + 1); /*0xaf798*/
  while ( v35 != (int *)((char *)&dword_44 + 2) ) /*0xaf7b8*/
  {
    if ( v35 != (int *)((char *)&dword_104 + 1) ) /*0xaf7c4*/
    {
      if ( v35 == (int *)((char *)&dword_110 + 1) ) /*0xaf7cc*/
      {
        v35 = &dword_44 + 2; /*0xaf804*/
      }
      else if ( v35 == (int *)((char *)&dword_14 + 1) ) /*0xaf7d4*/
      {
        v35 = (_DWORD *)(&stru_210 + 8); /*0xaf7e4*/
        if ( a10 > 3 ) /*0xaf7f4*/
          a10 = 214; /*0xaf7f4*/
      }
    }
  }
  v13 = sub_AF3C0("__b_a_n_g_c_l_e__check1234567_", "__b_a_n_g_", 10); /*0xaf858*/
  v14 = sub_AF3C0("c_l_e__check1234567_", "c_l_e__che", 10); /*0xaf870*/
  v15 = sub_AF3C0("ck1234567_", "ck1234567_", 10); /*0xaf880*/
  v16 = v14 == 0; /*0xaf884*/
  if ( !v14 ) /*0xaf888*/
    v16 = v13 == 0; /*0xaf888*/
  if ( !v16 || v15 ) /*0xaf894*/
    sub_AF4E8("__b_a_n_g_c_l_e__check1234567_"); /*0xaf9ec*/
  v17 = a1 + 7; /*0xaf898*/
  v18 = a1[8]; /*0xaf89c*/
  v19 = a2 - a1[3]; /*0xaf8b0*/
  v20 = v19 + a1[9]; /*0xaf8b8*/
  v21 = ((v18 + a1[7] + 4095 + v20) & 0xFFFFF000) - v19; /*0xaf8cc*/
  v22 = a1[10]; /*0xaf8dc*/
  if ( sub_AF2B4(v19, v21, 7) ) /*0xaf8e0*/
    sub_AF2B4(v19, v21, 3); /*0xaf8f8*/
  sub_AFBD0(v20, a3, a1[7], a1[10]); /*0xaf90c*/
  if ( v18 ) /*0xaf914*/
  {
    for ( i = 0; i < v18; i += 4 ) /*0xaf92c*/
    {
      v25 = i + *v17; /*0xaf93c*/
      *(_DWORD *)(v20 + v25) ^= v18; /*0xaf94c*/
    }
  }
  if ( a1[7] >= 0x100000u ) /*0xaf920*/
  {
    for ( j = v20; j < v20 + 3201; j = v27 ) /*0xaf958*/
    {
      v27 = j + 64; /*0xaf968*/
      sub_AF2C8(); /*0xaf970*/
    }
  }
  else
  {
    for ( k = v20; k < v20 + *v17 + 1; k = v32 ) /*0xaf924*/
    {
      v32 = k + 64; /*0xaf9bc*/
      sub_AF2C8(); /*0xaf9c4*/
    }
  }
  v28 = *(unsigned __int16 *)(v19 + 42); /*0xaf980*/
  v29 = (_DWORD *)(v19 + *(_DWORD *)(v19 + 28)); /*0xaf988*/
  v30 = v28 * *(unsigned __int16 *)(v19 + 44) + 52; /*0xaf994*/
  v31 = *v29 == 1; /*0xaf9a0*/
  do /*0xaf9e0*/
  {
    v33 = *(_DWORD *)((char *)v29 + v28); /*0xaf9d0*/
    v29 = (_DWORD *)((char *)v29 + v28); /*0xaf9d0*/
    if ( v33 == 1 ) /*0xaf9d8*/
      ++v31; /*0xaf9d8*/
  }
  while ( v31 != 2 ); /*0xaf9e0*/
  sub_AF2B4( /*0xafa24*/
    (v19 + v29[2]) & 0xFFFFF000,
    ((v29[5] + 4095 + v19 + v29[2]) & 0xFFFFF000) - ((v19 + v29[2]) & 0xFFFFF000),
    3);
  sub_AF618(v19 + a1[6], v19 + a1[4], a1[5], v19, v30); /*0xafa44*/
  sub_AF2B4(v19, v21, 7); /*0xafa54*/
  sub_AF2A0(a3, v22); /*0xafa60*/
  return 0; /*0xafa6c*/
}
