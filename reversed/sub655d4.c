/*
 * Dynamic Trampoline Generator
 *
 * Generates self-modifying Thumb/ARM trampolines for runtime hook redirection.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file sub655d4.c
 * @brief Generates self-modifying Thumb/ARM trampolines for runtime hook redirection.
 *
 * Constructs dynamic jump trampolines for ART function intercepts.
 */

int sub_655D4()
{
  int v0; // r3
  int (*v1)(void); // r0

  v0 = 2; /*0x655de*/
  v1 = nullsub_4; /*0x655e0*/
  do /*0x655ee*/
  {
    *(_DWORD *)v1 ^= v0; /*0x655e6*/
    v1 = (int (*)(void))((char *)v1 + 1); /*0x655e8*/
    --v0; /*0x655ea*/
  }
  while ( v0 ); /*0x655ee*/
  return nullsub_4();
}
