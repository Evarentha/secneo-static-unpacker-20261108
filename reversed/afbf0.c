/*
 * SecNeo Proprietary LZ Decompressor
 *
 * Decompiled native decompression algorithm used across container and .so payloads.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file afbf0.c
 * @brief Decompiled native decompression algorithm used across container and .so payloads.
 *
 * Implements proprietary sliding-dictionary LZ decompression into memory.
 */

int __fastcall sub_AFBF0(int a1, unsigned int a2, int a3, _DWORD *a4)
{
  int v4; // r5
  unsigned int v5; // r7
  unsigned int v6; // r12
  int v7; // r4
  bool v8; // zf
  char v9; // r6
  int i; // r6
  bool v11; // zf
  int v12; // r4
  bool v13; // zf
  unsigned int v14; // r8
  unsigned int v15; // r4
  int v16; // r6
  int v17; // r6
  bool v18; // zf
  int v19; // r6
  int v20; // r6
  unsigned int v21; // r8
  bool v22; // zf
  int v23; // r6
  unsigned int v24; // r7
  bool v25; // zf
  int v26; // r6
  int v27; // r6
  int v28; // r6
  bool v29; // zf
  int v30; // r4
  bool v31; // zf
  unsigned int v32; // r8
  int v33; // r6
  int v34; // r8
  _BYTE *v35; // r6
  int v36; // r9
  _BYTE *v37; // r10
  int v38; // r5
  char v39; // t1

  v4 = 0; /*0xafbf4*/
  v5 = 1; /*0xafbf8*/
  v6 = 0; /*0xafbfc*/
  v7 = 0; /*0xafc00*/
  while ( 1 ) /*0xafc20*/
  {
    while ( 1 ) /*0xafc04*/
    {
      v8 = (v7 & 0x7F) == 0; /*0xafc04*/
      if ( (v7 & 0x7F) != 0 ) /*0xafc08*/
        v7 *= 2; /*0xafc0c*/
      else
        v7 = *(unsigned __int8 *)(a1 + v6); /*0xafc08*/
      if ( v8 ) /*0xafc10*/
      {
        v7 = 2 * v7 + 1; /*0xafc14*/
        ++v6; /*0xafc18*/
      }
      if ( (v7 & 0x100) == 0 ) /*0xafc20*/
        break; /*0xafc20*/
      v9 = *(_BYTE *)(a1 + v6++); /*0xafc20*/
      *(_BYTE *)(a3 + v4++) = v9; /*0xafc28*/
    }
    for ( i = 1; ; i = v20 + ((unsigned int)(v7 << 23) >> 31) ) /*0xafc34*/
    {
      v11 = (v7 & 0x7F) == 0; /*0xafc38*/
      if ( (v7 & 0x7F) != 0 ) /*0xafc3c*/
        v12 = 2 * v7; /*0xafc40*/
      else
        v12 = *(unsigned __int8 *)(a1 + v6); /*0xafc3c*/
      if ( v11 ) /*0xafc44*/
      {
        v12 = 2 * v12 + 1; /*0xafc48*/
        ++v6; /*0xafc4c*/
      }
      v13 = (v12 & 0x7F) == 0; /*0xafc50*/
      v14 = v12 << 23; /*0xafc54*/
      if ( (v12 & 0x7F) != 0 ) /*0xafc58*/
        v15 = 2 * v12; /*0xafc5c*/
      else
        v15 = *(unsigned __int8 *)(a1 + v6); /*0xafc58*/
      if ( v13 ) /*0xafc60*/
        v15 = 2 * v15 + 1; /*0xafc64*/
      v16 = 2 * i; /*0xafc68*/
      if ( v13 ) /*0xafc6c*/
        ++v6; /*0xafc6c*/
      v17 = v16 + (v14 >> 31); /*0xafc74*/
      if ( (v15 & 0x100) != 0 ) /*0xafc78*/
        break; /*0xafc78*/
      v18 = (v15 & 0x7F) == 0; /*0xafc7c*/
      if ( (v15 & 0x7F) == 0 ) /*0xafc80*/
        v15 = *(unsigned __int8 *)(a1 + v6); /*0xafc80*/
      v19 = v17 + 0x7FFFFFFF; /*0xafc84*/
      v7 = 2 * v15; /*0xafc88*/
      if ( v18 ) /*0xafc90*/
        ++v7; /*0xafc90*/
      v20 = 2 * v19; /*0xafc94*/
      if ( v18 ) /*0xafc9c*/
        ++v6; /*0xafc9c*/
    }
    v21 = v6; /*0xafcac*/
    if ( v17 != 2 ) /*0xafcb0*/
      break; /*0xafcb0*/
    v22 = (v15 & 0x7F) == 0; /*0xafcb4*/
    if ( (v15 & 0x7F) != 0 ) /*0xafcb8*/
      v15 *= 2; /*0xafcbc*/
    else
      v15 = *(unsigned __int8 *)(a1 + v6); /*0xafcb8*/
    if ( v22 ) /*0xafcc0*/
    {
      v15 = 2 * v15 + 1; /*0xafcc4*/
      ++v6; /*0xafccc*/
    }
    v23 = (v15 >> 8) & 1; /*0xafcd0*/
LABEL_39:
    v25 = (v15 & 0x7F) == 0; /*0xafd04*/
    if ( (v15 & 0x7F) != 0 ) /*0xafd08*/
      v7 = 2 * v15; /*0xafd0c*/
    else
      v7 = *(unsigned __int8 *)(a1 + v6); /*0xafd08*/
    if ( v25 ) /*0xafd10*/
      v7 = 2 * v7 + 1; /*0xafd14*/
    v26 = 2 * v23; /*0xafd18*/
    if ( v25 ) /*0xafd20*/
      ++v6; /*0xafd20*/
    v27 = v26 + ((unsigned int)(v7 << 23) >> 31); /*0xafd24*/
    if ( !v27 ) /*0xafd28*/
    {
      v28 = 1; /*0xafd2c*/
      do /*0xafd70*/
      {
        v29 = (v7 & 0x7F) == 0; /*0xafd30*/
        if ( (v7 & 0x7F) != 0 ) /*0xafd34*/
          v30 = 2 * v7; /*0xafd38*/
        else
          v30 = *(unsigned __int8 *)(a1 + v6); /*0xafd34*/
        if ( v29 ) /*0xafd3c*/
        {
          v30 = 2 * v30 + 1; /*0xafd40*/
          ++v6; /*0xafd44*/
        }
        v31 = (v30 & 0x7F) == 0; /*0xafd48*/
        v32 = v30 << 23; /*0xafd4c*/
        if ( (v30 & 0x7F) != 0 ) /*0xafd50*/
          v7 = 2 * v30; /*0xafd54*/
        else
          v7 = *(unsigned __int8 *)(a1 + v6); /*0xafd50*/
        if ( v31 ) /*0xafd58*/
          v7 = 2 * v7 + 1; /*0xafd5c*/
        v33 = 2 * v28; /*0xafd60*/
        if ( v31 ) /*0xafd64*/
          ++v6; /*0xafd64*/
        v28 = v33 + (v32 >> 31); /*0xafd6c*/
      }
      while ( (v7 & 0x100) == 0 ); /*0xafd70*/
      v27 = v28 + 2; /*0xafd74*/
    }
    if ( v5 > 0x500 ) /*0xafd7c*/
      v34 = v27 + 1; /*0xafd80*/
    else
      v34 = v27; /*0xafd7c*/
    v35 = (_BYTE *)(a3 + v4 - v5); /*0xafd8c*/
    *(_BYTE *)(a3 + v4) = *v35; /*0xafd90*/
    v36 = v4 + 1; /*0xafd94*/
    v37 = &v35[v34]; /*0xafd98*/
    v38 = a3 + v4; /*0xafd9c*/
    do /*0xafdac*/
    {
      v39 = *++v35; /*0xafda0*/
      *(_BYTE *)++v38 = v39; /*0xafda8*/
    }
    while ( v35 != v37 ); /*0xafdac*/
    v4 = v36 + v34; /*0xafdb0*/
  }
  v24 = *(unsigned __int8 *)(a1 + v6++) + ((v17 + 16777213) << 8); /*0xafce4*/
  if ( v24 != -1 ) /*0xafcf0*/
  {
    v23 = !(*(_BYTE *)(a1 + v21) & 1); /*0xafcfc*/
    v5 = (v24 >> 1) + 1; /*0xafd00*/
    goto LABEL_39; /*0xafd00*/
  }
  *a4 = v4; /*0xafdbc*/
  if ( v6 == a2 ) /*0xafdc0*/
    return 0; /*0xafdd0*/
  if ( v6 >= a2 ) /*0xafdc4*/
    return -201; /*0xafdd8*/
  return -205; /*0xafdcc*/
}
