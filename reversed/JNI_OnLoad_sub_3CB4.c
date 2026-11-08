/*
 * SecNeo JNI Initialization & Cache Staging Handler
 *
 * Decompiled JNI_OnLoad implementation registering native methods.
 *
 * Authors:
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: MIT
 */

/**
 * @file JNI_OnLoad_sub_3CB4.c
 * @brief Decompiled JNI_OnLoad implementation registering native methods.
 *
 * Registers native methods AW.hn/pn and H.d, setting up cache file paths.
 */

int __fastcall sub_3CB4(int a1)
{
  int v1; // r4
  _DWORD *v2; // r8
  _DWORD *v3; // r10
  int v4; // r6
  _DWORD *v5; // r4
  int v6; // r5
  void (__fastcall *v7)(__int64 *, unsigned int); // r5
  void (__fastcall *v8)(__int64 *, unsigned int); // r9
  void (__fastcall *v9)(__int64 *, unsigned int); // r11
  int v10; // r10
  int v11; // r10
  int v12; // r5
  int v13; // r5
  int v14; // r5
  int v15; // r5
  int v16; // r4
  int v17; // r6
  int v18; // r5
  int v19; // r1
  unsigned int v20; // r6
  int v21; // r5
  int v22; // r0
  int v23; // r0
  int v24; // r0
  int v25; // r5
  int v26; // r4
  int v27; // r0
  int v28; // r0
  int v29; // r0
  int v30; // r0
  int *v31; // r1
  int v32; // r9
  int v33; // r4
  int v34; // r0
  int v35; // r1
  int v36; // r4
  int v37; // r6
  int v38; // r8
  int v39; // r5
  int v40; // r4
  int v41; // r0
  __int64 i; // r0
  int v43; // r5
  BOOL v44; // r4
  int v45; // r4
  _DWORD *v46; // r5
  BOOL v47; // r0
  int *v48; // r1
  int v49; // r1
  int v50; // r0
  BOOL v51; // r0
  int v52; // r0
  int v53; // r4
  int v54; // r0
  int v55; // r0
  int v56; // r11
  int v57; // r9
  int v58; // r0
  int v59; // r0
  int v60; // r0
  int v61; // r0
  int v62; // r4
  int v63; // r5
  int v64; // r0
  int v65; // r0
  char *v66; // r4
  int v67; // r0
  int v68; // r0
  int v69; // r0
  int v70; // r4
  int v71; // r0
  int v72; // r5
  int v73; // r0
  int v74; // r11
  int v75; // r0
  int v76; // r6
  int v77; // r5
  int v78; // r0
  int v79; // r0
  int v80; // t1
  int v81; // r0
  int v82; // r5
  int v83; // r0
  int v84; // r4
  int v85; // r0
  int v86; // r0
  int v87; // r8
  const char *v88; // r2
  int v89; // r1
  void (*v90)(int, int, const char *, ...); // r6
  int v91; // r4
  int v92; // r0
  int v93; // r0
  int v94; // r5
  __int64 v95; // r0
  __int64 v96; // r0
  int *v97; // r0
  int v98; // r6
  int v99; // r0
  int v100; // r5
  int v101; // r1
  int v102; // r6
  int v103; // r0
  int v104; // r0
  _BYTE *v105; // r5
  char *v106; // r1
  int v107; // r0
  int v108; // r0
  int **v109; // r9
  int v110; // r0
  int *v111; // r1
  unsigned int v112; // r3
  int v113; // r0
  int v114; // r0
  int v116; // r0
  int v117; // r0
  int v118; // r5
  int v119; // r9
  int v120; // r0
  int v121; // r3
  int v122; // r11
  int v123; // r6
  int v124; // r3
  int v125; // r0
  int *v126; // r5
  int v127; // r1
  bool v128; // zf
  int v129; // r1
  int v130; // r1
  bool v131; // zf
  bool v132; // zf
  void (__fastcall *v133)(int, int (*)(), unsigned int); // r9
  int v134; // [sp+Ch] [bp-98Ch]
  int v135; // [sp+10h] [bp-988h]
  const char *v136; // [sp+14h] [bp-984h]
  _DWORD *v137; // [sp+18h] [bp-980h]
  int *v138; // [sp+1Ch] [bp-97Ch]
  unsigned int v139; // [sp+20h] [bp-978h]
  _DWORD *v140; // [sp+24h] [bp-974h] BYREF
  __int64 v141; // [sp+28h] [bp-970h] BYREF
  _QWORD v142[2]; // [sp+30h] [bp-968h]
  _DWORD v143[256]; // [sp+40h] [bp-958h] BYREF
  __int64 v144; // [sp+440h] [bp-558h] BYREF
  _BYTE v145[20]; // [sp+448h] [bp-550h]
  const char *v146; // [sp+45Ch] [bp-53Ch]
  int v147; // [sp+460h] [bp-538h]
  __int64 v148; // [sp+840h] [bp-158h] BYREF
  _QWORD v149[2]; // [sp+848h] [bp-150h]
  _DWORD v150[64]; // [sp+858h] [bp-140h] BYREF
  __int64 v151; // [sp+958h] [bp-40h] BYREF
  _QWORD v152[3]; // [sp+960h] [bp-38h]
  int v153; // [sp+978h] [bp-20h]

  v3 = (_DWORD *)MEMORY[0x6EE20]; /*0x3cca*/
  v153 = *MEMORY[0x6EE20]; /*0x3cd2*/
  v140 = 0; /*0x3cd6*/
  if ( (*(int (__fastcall **)(int, _DWORD **, int))(*(_DWORD *)a1 + 24))(a1, &v140, 65540) ) /*0x3cde*/
  {
    v4 = -1; /*0x3ce2*/
    goto LABEL_146; /*0x3ce6*/
  }
  v137 = v3; /*0x3cea*/
  v5 = v140; /*0x3cee*/
  *(_DWORD *)v145 = MEMORY[0x6EE34]; /*0x3cf6*/
  HIDWORD(v144) = "(Ljava/lang/String;)I"; /*0x3cfe*/
  LODWORD(v144) = v143; /*0x3d04*/
  *(_DWORD *)&v145[12] = MEMORY[0x6EE38]; /*0x3d0e*/
  *(_DWORD *)&v145[8] = "(Ljava/lang/String;I)V"; /*0x3d16*/
  *(_DWORD *)&v145[4] = v150; /*0x3d1e*/
  v143[0] = 6383719; /*0x3d24*/
  v150[0] = 6383731; /*0x3d28*/
  v147 = MEMORY[0x6EE3C]; /*0x3d32*/
  v146 = "(I)V"; /*0x3d3e*/
  *(_DWORD *)&v145[16] = &v151; /*0x3d46*/
  strcpy((char *)&v151, "he"); /*0x3d4e*/
  v136 = "com/secneo/apkwrapper/H"; /*0x3d5c*/
  v6 = (*(int (__fastcall **)(_DWORD *))(*v140 + 24))(v140); /*0x3d60*/
  (*(void (__fastcall **)(_DWORD *, int, __int64 *, int))(*v5 + 860))(v5, v6, &v144, 3); /*0x3d72*/
  if ( v6 ) /*0x3d74*/
    (*(void (__fastcall **)(_DWORD *, int))(*v5 + 92))(v5, v6); /*0x3d7e*/
  (*(void (__fastcall **)(_DWORD *, _DWORD))(*v140 + 876))(v140, MEMORY[0x6EE40]); /*0x3d8e*/
  sub_344(&v144, 0x70B7Eu, sub_9538, 0); /*0x3da2*/
  v7 = (void (__fastcall *)(__int64 *, unsigned int))MEMORY[0x6EE44]; /*0x3dae*/
  MEMORY[0x6EE44](&v144, 0x74F9Cu); /*0x3db4*/
  v7(&v144, 0x74F9Du); /*0x3dba*/
  v8 = (void (__fastcall *)(__int64 *, unsigned int))MEMORY[0x6EE48]; /*0x3dc2*/
  MEMORY[0x6EE48](&v144, 0x74FA0u); /*0x3dc8*/
  v7(&v144, 0x74FA4u); /*0x3dd0*/
  v7(&v144, 0x74FA5u); /*0x3dd8*/
  v7(&v144, 0x74FA6u); /*0x3de0*/
  v7(&v144, 0x74FA7u); /*0x3de8*/
  v9 = (void (__fastcall *)(__int64 *, unsigned int))MEMORY[0x6EE4C]; /*0x3df2*/
  MEMORY[0x6EE4C](&v144, 0x74FA8u); /*0x3df8*/
  v10 = MEMORY[0x74FA8]; /*0x3dfa*/
  MEMORY[0x74FAC] = sub_254(MEMORY[0x74FA8]); /*0x3e06*/
  sub_350(&v144, MEMORY[0x74FAC], v10); /*0x3e0c*/
  v7(&v144, 0x74FB0u); /*0x3e16*/
  v9(&v144, 0x74FB4u); /*0x3e1e*/
  v11 = MEMORY[0x74FB4]; /*0x3e20*/
  MEMORY[0x74FB8] = sub_254(MEMORY[0x74FB4]); /*0x3e2c*/
  sub_350(&v144, MEMORY[0x74FB8], v11); /*0x3e32*/
  v7(&v144, 0x74FBCu); /*0x3e3c*/
  v7(&v144, 0x74FBDu); /*0x3e44*/
  v7(&v144, 0x74FBEu); /*0x3e4c*/
  v7(&v144, 0x74FBFu); /*0x3e54*/
  v7(&v144, 0x74FC0u); /*0x3e5c*/
  v7(&v144, 0x74FCCu); /*0x3e64*/
  v7(&v144, 0x74FCDu); /*0x3e6c*/
  v7(&v144, 0x74FCEu); /*0x3e74*/
  v8(&v144, 0x750D0u); /*0x3e7c*/
  v7(&v144, 0x750D4u); /*0x3e84*/
  v8(&v144, 0x750D8u); /*0x3e8c*/
  v8(&v144, 0x750FCu); /*0x3e94*/
  v9(&v144, 0x75100u); /*0x3e9c*/
  v12 = MEMORY[0x75100]; /*0x3e9e*/
  if ( MEMORY[0x75100] ) /*0x3ea2*/
  {
    MEMORY[0x75104] = sub_254(MEMORY[0x75100] + 1); /*0x3eac*/
    sub_350(&v144, MEMORY[0x75104], v12); /*0x3eb6*/
    *(_BYTE *)(MEMORY[0x75104] + MEMORY[0x75100]) = 0; /*0x3ebe*/
  }
  else
  {
    MEMORY[0x75104] = 0; /*0x3ec2*/
  }
  sub_35C(&v144, 0x75108u); /*0x3ece*/
  v13 = MEMORY[0x75108]; /*0x3ed2*/
  if ( MEMORY[0x75108] ) /*0x3ed6*/
  {
    MEMORY[0x7510C] = sub_254(MEMORY[0x75108] + 1); /*0x3ee0*/
    sub_350(&v144, MEMORY[0x7510C], v13); /*0x3eea*/
    *(_BYTE *)(MEMORY[0x7510C] + MEMORY[0x75108]) = 0; /*0x3ef4*/
  }
  else
  {
    MEMORY[0x7510C] = 0; /*0x3efa*/
  }
  sub_35C(&v144, 0x750DCu); /*0x3f08*/
  v14 = MEMORY[0x750DC]; /*0x3f0c*/
  MEMORY[0x750E0] = sub_254(MEMORY[0x750DC]); /*0x3f18*/
  sub_350(&v144, MEMORY[0x750E0], v14); /*0x3f20*/
  sub_368(&v144, 0x750E4u); /*0x3f2a*/
  sub_368(&v144, 0x750E5u); /*0x3f34*/
  v150[0] = 0; /*0x3f3e*/
  sub_374(&v144, v150); /*0x3f44*/
  if ( v150[0] ) /*0x3f4c*/
  {
    sub_35C(&v144, v143); /*0x3f56*/
    sub_350(&v144, 0x74FCFu, v143[0]); /*0x3f62*/
  }
  sub_374(&v144, 0x750F0u); /*0x3f70*/
  v15 = MEMORY[0x750F0]; /*0x3f74*/
  if ( MEMORY[0x750F0] >= 1 ) /*0x3f7c*/
  {
    v16 = 0; /*0x3f88*/
    v17 = 12; /*0x3f8a*/
    MEMORY[0x750F4] = sub_254(16 * MEMORY[0x750F0]); /*0x3f8e*/
    while ( v16 < v15 ) /*0x3f94*/
    {
      v8(&v144, MEMORY[0x750F4] + v17 - 12); /*0x3fa4*/
      v8(&v144, MEMORY[0x750F4] + v17 - 8); /*0x3fb2*/
      v8(&v144, MEMORY[0x750F4] + v17 - 4); /*0x3fbe*/
      v8(&v144, MEMORY[0x750F4] + v17); /*0x3fc8*/
      v17 += 16; /*0x3fca*/
      ++v16; /*0x3fcc*/
      v15 = MEMORY[0x750F0]; /*0x3fce*/
    }
  }
  if ( MEMORY[0x74FC0] ) /*0x401c*/
  {
    sub_35C(&v144, 0x74FC4u); /*0x4028*/
    v18 = MEMORY[0x74FC4]; /*0x402c*/
    MEMORY[0x74FC8] = sub_254(MEMORY[0x74FC4] + 1); /*0x4038*/
    sub_350(&v144, MEMORY[0x74FC8], v18); /*0x4040*/
    *(_BYTE *)(MEMORY[0x74FC8] + MEMORY[0x74FC4]) = 0; /*0x404a*/
  }
  v19 = MEMORY[0x6EE28]; /*0x4050*/
  *MEMORY[0x6EE28] = 0x74F9Cu; /*0x4052*/
  v3 = v140; /*0x4058*/
  v20 = 0x77060u; /*0x405c*/
  v138 = (int *)0x6EE24; /*0x4066*/
  v139 = 0x77060u; /*0x4066*/
  if ( MEMORY[0x7706C] ) /*0x406a*/
    goto LABEL_117; /*0x406a*/
  v135 = v19; /*0x406e*/
  v21 = sub_254(584); /*0x407e*/
  MEMORY[0x7706C] = v21; /*0x4080*/
  *(_DWORD *)(v21 + 36) = 7172705; /*0x408a*/
  strcpy((char *)(v21 + 52), "com/secneo/apkwrapper/H"); /*0x4094*/
  strcpy((char *)(v21 + 248), "com/secneo/apkwrapper/AW"); /*0x40ae*/
  v22 = (*(int (__fastcall **)(_DWORD *))(*v3 + 24))(v3); /*0x40c6*/
  *(_DWORD *)(v21 + 116) = (*(int (__fastcall **)(_DWORD *, int))(*v3 + 84))(v3, v22); /*0x40d4*/
  v23 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 24))(v3, "com/secneo/apkwrapper/AW"); /*0x40e0*/
  *(_DWORD *)(v21 + 312) = (*(int (__fastcall **)(_DWORD *, int))(*v3 + 84))(v3, v23); /*0x40ee*/
  v144 = *(_QWORD *)L"dro0d1c2f0EF"; /*0x40fc*/
  v145[0] = aDro0d1c2f0ef[4]; /*0x40fc*/
  *(_QWORD *)&v145[1] = *(_QWORD *)((char *)L"d1c2f0EF" + 1); /*0x4106*/
  *(_QWORD *)&v145[9] = *(_QWORD *)((char *)L"f0EF" + 1); /*0x4106*/
  ((void (__fastcall *)(__int64 *, int))loc_82C4)(&v144, 24); /*0x410c*/
  v24 = sub_134(&v144); /*0x4112*/
  sub_17C(v21 + 316, &v144, v24 + 1); /*0x4120*/
  v25 = MEMORY[0x7706C]; /*0x4128*/
  v26 = (*(int (__fastcall **)(_DWORD *, int))(*v3 + 24))(v3, MEMORY[0x7706C] + 52); /*0x4134*/
  v27 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 576))( /*0x414a*/
          v3,
          v26,
          "PKGNAME",
          "Ljava/lang/String;");
  v28 = (*(int (__fastcall **)(_DWORD *, int, int))(*v3 + 580))(v3, v26, v27); /*0x415a*/
  v29 = (*(int (__fastcall **)(_DWORD *, int, _DWORD))(*v3 + 676))(v3, v28, 0); /*0x416a*/
  sub_284(v25 + 120, v29); /*0x4172*/
  sub_B0(&v144, 92); /*0x417e*/
  if ( sub_9668("ro.build.version.sdk", &v144, a0nopqrs) < 1 ) /*0x4192*/
  {
    v30 = -1; /*0x41d0*/
  }
  else
  {
    v30 = sub_380(&v144); /*0x4198*/
    switch ( v30 ) /*0x41a6*/
    {
      case 23: /*0x41a6*/
        sub_9668("ro.build.version.release", &v144, a0nopqrs); /*0x41be*/
        v30 = 23; /*0x41c6*/
        if ( (unsigned __int16)v144 == 78 ) /*0x41ca*/
          v30 = 24; /*0x41cc*/
        break; /*0x41cc*/
      case 25: /*0x41a6*/
        sub_9668("ro.build.version.release", &v144, a0nopqrs); /*0x41e4*/
        v30 = 25; /*0x41ec*/
        if ( (unsigned __int16)v144 == 79 ) /*0x41f0*/
          v30 = 26; /*0x41f2*/
        break; /*0x41f2*/
      case 27: /*0x41a6*/
        sub_9668("ro.build.version.release", &v144, a0nopqrs); /*0x4202*/
        if ( (unsigned __int16)v144 == 80 ) /*0x420c*/
          goto LABEL_31; /*0x420c*/
        v30 = 27; /*0x420e*/
        break; /*0x4210*/
      case 28: /*0x41a6*/
LABEL_31:
        sub_9668("ro.build.version.release", &v144, a0nopqrs); /*0x4212*/
        if ( (unsigned __int16)v144 == 81 ) /*0x4228*/
          goto LABEL_34; /*0x4228*/
        sub_9668("ro.build.version.codename", &v144, a0nopqrs); /*0x4236*/
        if ( (unsigned __int16)v144 == 81 ) /*0x4240*/
          goto LABEL_34; /*0x4240*/
        v30 = 28; /*0x4242*/
        break; /*0x4244*/
      case 29: /*0x41a6*/
LABEL_34:
        sub_9668("ro.build.version.release", &v144, a0nopqrs); /*0x4246*/
        if ( (unsigned __int16)v144 == 82 ) /*0x425c*/
          goto LABEL_37; /*0x425c*/
        sub_9668("ro.build.version.codename", &v144, a0nopqrs); /*0x426a*/
        if ( (unsigned __int16)v144 == 82 ) /*0x4274*/
          goto LABEL_37; /*0x4274*/
        v30 = 29; /*0x4276*/
        break; /*0x4278*/
      case 30: /*0x41a6*/
LABEL_37:
        sub_9668("ro.build.version.codename", &v144, a0nopqrs); /*0x427a*/
        v30 = 30; /*0x428e*/
        if ( (unsigned __int16)v144 == 83 ) /*0x4292*/
          v30 = 31; /*0x4294*/
        break; /*0x4294*/
      default:
        break;
    }
  }
  v31 = (int *)MEMORY[0x7706C]; /*0x4296*/
  *MEMORY[0x7706C] = v30; /*0x4298*/
  *MEMORY[0x6EE50] = v30; /*0x42a0*/
  if ( *v31 < 31 ) /*0x42a6*/
    goto LABEL_55; /*0x42a6*/
  v32 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 24))(v3, "android/content/pm/PackageManager"); /*0x42b8*/
  v33 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 576))(v3, v32, "MATCH_APEX", "I"); /*0x42d0*/
  v34 = (*(int (__fastcall **)(_DWORD *))(*v3 + 912))(v3); /*0x42dc*/
  v35 = *v3; /*0x42de*/
  if ( !v33 || v34 ) /*0x42ea*/
  {
    (*(void (__fastcall **)(_DWORD *))(v35 + 68))(v3); /*0x445c*/
    if ( v32 ) /*0x4462*/
      (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v32); /*0x446e*/
LABEL_55:
    v43 = 0; /*0x4470*/
    goto LABEL_56; /*0x4470*/
  }
  v36 = (*(int (__fastcall **)(_DWORD *, int, int))(v35 + 600))(v3, v32, v33); /*0x42fa*/
  v37 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 668))(v3, "com.google.android.art"); /*0x430c*/
  v38 = sub_969C(v3, v37, v36); /*0x4318*/
  if ( (*(int (__fastcall **)(_DWORD *))(*v3 + 912))(v3) ) /*0x4324*/
    (*(void (__fastcall **)(_DWORD *))(*v3 + 68))(v3); /*0x4330*/
  if ( v38 ) /*0x4336*/
    goto LABEL_50; /*0x4336*/
  v39 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 668))(v3, "com.android.art"); /*0x4348*/
  v38 = sub_969C(v3, v39, v36); /*0x4354*/
  if ( (*(int (__fastcall **)(_DWORD *))(*v3 + 912))(v3) ) /*0x4360*/
    (*(void (__fastcall **)(_DWORD *))(*v3 + 68))(v3); /*0x436c*/
  if ( v39 ) /*0x436e*/
    (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v39); /*0x437a*/
  if ( v38 ) /*0x4380*/
  {
LABEL_50:
    v40 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 24))(v3, "android/content/pm/PackageInfo"); /*0x4392*/
    v41 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 132))( /*0x43a8*/
            v3,
            v40,
            "getLongVersionCode",
            "()J");
    for ( i = sub_38C(v3, v38, v41); ; LODWORD(i) = sub_54910(i, HIDWORD(i), 10, 0) ) /*0x43b0*/
    {
      v43 = i; /*0x43b4*/
      if ( i < 101 ) /*0x43bc*/
        break; /*0x43bc*/
    }
    if ( v40 ) /*0x44bc*/
      (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v40); /*0x44c8*/
    v45 = 1; /*0x44ca*/
  }
  else
  {
    v45 = 0; /*0x4fd6*/
    v38 = 0; /*0x4fd8*/
    v43 = 0; /*0x4fdc*/
  }
  if ( v37 ) /*0x44cc*/
    (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v37); /*0x44d8*/
  if ( v45 ) /*0x44da*/
    (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v38); /*0x44e6*/
  if ( v32 ) /*0x44ee*/
    (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v32); /*0x44fa*/
LABEL_56:
  v44 = 0; /*0x4472*/
  *(_DWORD *)(MEMORY[0x7706C] + 20) = v43; /*0x4478*/
  sub_D4("/system/lib/libdvm.so", 0); /*0x447e*/
  sub_D4("/system/lib/libart.so", 0); /*0x4488*/
  if ( (int)*MEMORY[0x7706C] >= 21 ) /*0x4492*/
    v44 = sub_9668("persist.sys.dalvik.vm.lib", &v144, &byte_5DA57) < 1 || sub_398(&v144, "libdvm", 6); /*0x44b8*/
  v46 = (_DWORD *)MEMORY[0x7706C]; /*0x4500*/
  *(_DWORD *)(MEMORY[0x7706C] + 4) = v44; /*0x4508*/
  sub_B0(&v144, 92); /*0x450a*/
  v47 = *v46 == 25 && sub_9668("ro.product.manufacturer", &v144, &byte_5DA57) >= 1 && !sub_398(&v144, "samsung", 7); /*0x4e34*/
  v48 = (int *)MEMORY[0x7706C]; /*0x453e*/
  *(_DWORD *)(MEMORY[0x7706C] + 16) = v47; /*0x4540*/
  if ( *v48 > 22 /*0x45ae*/
    || sub_9668("ro.yunos.version", &v144, &byte_5DA57) <= 0
    && sub_9668("ro.yunos.version.release", &v144, &byte_5DA57) <= 0
    && sub_9668("ro.yunos.product.model", &v144, &byte_5DA57) <= 0
    && sub_9668("ro.yunos.product.board", &v144, &byte_5DA57) <= 0
    && sub_9668("ro.yunos.product.device", &v144, &byte_5DA57) < 1 )
  {
    v49 = 0; /*0x4548*/
    goto LABEL_88; /*0x454a*/
  }
  if ( sub_9668("persist.sys.dalvik.vm.lib", &v144, &byte_5DA57) >= 1 && !sub_398(&v144, "libart", 6) ) /*0x45d2*/
  {
LABEL_86:
    v49 = 2; /*0x45fe*/
    goto LABEL_88; /*0x4600*/
  }
  if ( sub_9668("persist.sys.dalvik.vm.lib.2", &v144, &byte_5DA57) >= 1 ) /*0x45e6*/
  {
    v50 = sub_398(&v144, "libart", 6); /*0x45f2*/
    v49 = 1; /*0x45f6*/
    if ( v50 ) /*0x45f8*/
      goto LABEL_88; /*0x45f8*/
    *(_DWORD *)(MEMORY[0x7706C] + 4) = 1; /*0x45fc*/
    goto LABEL_86; /*0x45fc*/
  }
  v49 = 1; /*0x4602*/
LABEL_88:
  v2 = v143; /*0x4604*/
  *(_DWORD *)(MEMORY[0x7706C] + 8) = v49; /*0x460a*/
  sub_9668("ro.product.cpu.abi", v143, &byte_5DA57); /*0x4616*/
  if ( sub_3A4(v143, "x86") ) /*0x4620*/
  {
    v51 = 1; /*0x4626*/
  }
  else
  {
    v52 = sub_E0("/system/lib/libc.so", "r"); /*0x4632*/
    if ( v52 ) /*0x4636*/
    {
      v53 = v52; /*0x4638*/
      sub_3B0(&v144, 52, 1, v52); /*0x4644*/
      sub_EC(v53); /*0x464a*/
      v51 = *(unsigned __int16 *)&v145[10] == 3; /*0x4658*/
    }
    else
    {
      v51 = 0; /*0x465c*/
    }
  }
  v136 = (const char *)MEMORY[0x7706C]; /*0x4660*/
  *(_DWORD *)(MEMORY[0x7706C] + 24) = v51; /*0x4662*/
  v1 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 24))(v3, v136 + 52); /*0x4670*/
  if ( (*(int (__fastcall **)(_DWORD *))(*v3 + 912))(v3) ) /*0x467c*/
    (*(void (__fastcall **)(_DWORD *))(*v3 + 68))(v3); /*0x4688*/
  if ( !v1 ) /*0x468c*/
  {
    v56 = 0; /*0x4748*/
    goto LABEL_100; /*0x4748*/
  }
  v54 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 576))( /*0x46a2*/
          v3,
          v1,
          "sAppInfo",
          "Landroid/content/pm/ApplicationInfo;");
  v55 = (*(int (__fastcall **)(_DWORD *, int, int))(*v3 + 580))(v3, v1, v54); /*0x46b2*/
  if ( !v55 ) /*0x46b6*/
    goto LABEL_149; /*0x46b6*/
  v56 = v55; /*0x46ba*/
  while ( 2 ) /*0x46bc*/
  {
    (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v1); /*0x46bc*/
LABEL_100:
    v57 = (*(int (__fastcall **)(_DWORD *, int))(*v3 + 124))(v3, v56); /*0x474c*/
    v58 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 376))( /*0x4770*/
            v3,
            v57,
            "sourceDir",
            "Ljava/lang/String;");
    v59 = (*(int (__fastcall **)(_DWORD *, int, int))(*v3 + 380))(v3, v56, v58); /*0x4780*/
    v134 = (*(int (__fastcall **)(_DWORD *, int, _DWORD))(*v3 + 676))(v3, v59, 0); /*0x4794*/
    v60 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 376))( /*0x47a8*/
            v3,
            v57,
            "dataDir",
            "Ljava/lang/String;");
    v61 = (*(int (__fastcall **)(_DWORD *, int, int))(*v3 + 380))(v3, v56, v60); /*0x47b8*/
    v62 = (*(int (__fastcall **)(_DWORD *, int, _DWORD))(*v3 + 676))(v3, v61, 0); /*0x47ca*/
    v63 = *v138; /*0x47d0*/
    sub_260(*v138, 128); /*0x47d4*/
    v64 = sub_284(v63, v62); /*0x47dc*/
    v65 = sub_134(v64); /*0x47e0*/
    if ( *(_BYTE *)(v65 + v63 - 1) != 47 ) /*0x47ec*/
      *(_BYTE *)(v63 + v65) = 47; /*0x47f0*/
    v66 = (char *)MEMORY[0x6EE54]; /*0x47f8*/
    sub_260(MEMORY[0x6EE54] + 9, 247); /*0x47fe*/
    strcpy(v66, "/sdcard/"); /*0x480e*/
    v67 = **(_DWORD **)(v139 + 12); /*0x4814*/
    if ( v67 >= 9 ) /*0x4818*/
    {
      v68 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 376))( /*0x482e*/
              v3,
              v57,
              "nativeLibraryDir",
              "Ljava/lang/String;");
      v69 = (*(int (__fastcall **)(_DWORD *, int, int))(*v3 + 380))(v3, v56, v68); /*0x483e*/
      v70 = (*(int (__fastcall **)(_DWORD *, int, _DWORD))(*v3 + 676))(v3, v69, 0); /*0x4850*/
      v71 = sub_134(v70); /*0x4852*/
      v72 = sub_254(v71 + 1); /*0x485c*/
      *((_DWORD *)v136 + 144) = v72; /*0x4860*/
      v73 = sub_134(v70); /*0x4866*/
      sub_260(v72, v73 + 1); /*0x486e*/
      v67 = sub_284(v72, v70); /*0x4876*/
    }
    v74 = sub_170(v67); /*0x4886*/
    memset(v150, 0, 64); /*0x48a4*/
    v148 = *(_QWORD *)L"0stpf1&g1gg"; /*0x48b6*/
    v149[0] = *(_QWORD *)L"f1&g1gg"; /*0x48b6*/
    *(_QWORD *)((char *)v149 + 7) = *(_QWORD *)((char *)L"g1gg" + 1); /*0x48c0*/
    ((void (__fastcall *)(__int64 *, int))loc_82C4)(&v148, 22); /*0x48c6*/
    sub_BC(v150, &v148, v74); /*0x48d0*/
    v75 = sub_3BC(v150); /*0x48d6*/
    v76 = 0; /*0x48da*/
    if ( v75 ) /*0x48de*/
    {
      v77 = v75; /*0x48e0*/
      v151 = *(_QWORD *)L"0stpf1&g1gg1&g"; /*0x48f8*/
      v152[0] = *(_QWORD *)L"f1&g1gg1&g"; /*0x48f8*/
      *(_QWORD *)((char *)v152 + 5) = *(_QWORD *)((char *)L"&g1gg1&g" + 1); /*0x4902*/
      *(_QWORD *)((char *)&v152[1] + 5) = *(_QWORD *)((char *)L"g1&g" + 1); /*0x4902*/
      ((void (*)(void))loc_82C4)(); /*0x4906*/
      v141 = *(_QWORD *)L"0ecth0bsm"; /*0x491c*/
      v142[0] = *(_QWORD *)L"h0bsm"; /*0x491c*/
      *(_DWORD *)((char *)v142 + 7) = 27904; /*0x4920*/
      ((void (__fastcall *)(__int64 *, int))loc_82C4)(&v141, 18); /*0x4926*/
      while ( 1 ) /*0x4930*/
      {
        v78 = sub_3C8(v77); /*0x4930*/
        if ( !v78 ) /*0x4934*/
          break; /*0x4934*/
        v80 = *(unsigned __int8 *)(v78 + 19); /*0x4936*/
        v79 = v78 + 19; /*0x4936*/
        if ( (unsigned int)(v80 - 48) <= 9 ) /*0x493e*/
        {
          sub_380(v79); /*0x4940*/
          sub_BC(&v144, &v151, v74); /*0x494e*/
          *((_BYTE *)v2 + sub_9C7C(&v144, v2)) = 0; /*0x495a*/
          if ( sub_3A4(v2, v136 + 120) ) /*0x4962*/
          {
            if ( sub_9CA0(v2, ".apk") && (!*(_BYTE *)(*(_DWORD *)v135 + 312) || sub_9CA0(v2, &v141)) ) /*0x4986*/
            {
              sub_3D4(v77); /*0x4990*/
              v81 = sub_134(v143); /*0x4998*/
              v76 = sub_254(v81 + 1); /*0x49a4*/
              sub_284(v76, v143); /*0x49a6*/
              goto LABEL_114; /*0x49aa*/
            }
          }
        }
      }
      sub_3D4(v77); /*0x49ae*/
      v76 = 0; /*0x49b2*/
    }
LABEL_114:
    v82 = v134; /*0x49b4*/
    if ( v76 ) /*0x49b8*/
      v82 = v76; /*0x49ba*/
    v83 = sub_134(v82); /*0x49be*/
    v84 = sub_254(v83 + 1); /*0x49c8*/
    *((_DWORD *)v136 + 145) = v84; /*0x49cc*/
    v85 = sub_134(v82); /*0x49d2*/
    sub_260(v84, v85 + 1); /*0x49da*/
    sub_284(v84, v82); /*0x49e2*/
    v20 = v139; /*0x49ee*/
    *(_DWORD *)(*(_DWORD *)(v139 + 12) + 28) = ((int (__fastcall *)(const char *))loc_957C)("libart.so"); /*0x49f2*/
    *(_DWORD *)(*(_DWORD *)(v139 + 12) + 32) = ((int (__fastcall *)(const char *))loc_957C)("libdexfile.so"); /*0x49fe*/
    v3 = v140; /*0x4a00*/
LABEL_117:
    sub_3E0(v3); /*0x4a04*/
    v86 = *(_DWORD *)(v20 + 12); /*0x4a0a*/
    strcpy((char *)(v86 + 368), ".cache"); /*0x4a12*/
    *(_DWORD *)(v86 + 352) = 7627119; /*0x4a1e*/
    v87 = *(_DWORD *)v86; /*0x4a22*/
    if ( *(int *)v86 > 25 ) /*0x4a2a*/
      v88 = "%s/%s/%s"; /*0x4a8c*/
    else
      v88 = "%s"; /*0x4a32*/
    sub_C8(&v151, 32, v88, v86 + 368); /*0x4a90*/
    v89 = *(_DWORD *)(v20 + 12); /*0x4a94*/
    v3 = v137; /*0x4a96*/
    v90 = (void (*)(int, int, const char *, ...))MEMORY[0x6EE58]; /*0x4aac*/
    MEMORY[0x6EE58](v89 + 384, 64, "%s/%s", (const char *)(v89 + 368), "classes.jar"); /*0x4ab6*/
    v90(*(_DWORD *)(v139 + 12) + 448, 64, "%s/%s", (const char *)&v151, "classes.dex"); /*0x4ad0*/
    v90(*(_DWORD *)(v139 + 12) + 512, 64, "%s/%s", (const char *)&v151, "classes.odex"); /*0x4ae6*/
    sub_B0(v143, 256); /*0x4af2*/
    v91 = *v138; /*0x4afa*/
    sub_BC(v143, "%s%s", *v138); /*0x4b08*/
    if ( sub_D4(v143, 0) ) /*0x4b10*/
    {
      sub_3EC(v143, 509); /*0x4b1c*/
      if ( v87 >= 26 ) /*0x4b24*/
      {
        sub_BC(v143, "%s%s/%s", v91); /*0x4b3c*/
        sub_3EC(v143, 509); /*0x4b46*/
        sub_BC(v143, "%s%s/%s/%s", v91); /*0x4b64*/
        sub_3EC(v143, 509); /*0x4b6e*/
      }
    }
    v92 = sub_B0(&v144, 1024); /*0x4b7a*/
    sub_170(v92); /*0x4b7e*/
    v93 = sub_E0("/proc/self/cmdline", "r"); /*0x4b8a*/
    if ( v93 ) /*0x4b8e*/
    {
      v94 = v93; /*0x4b96*/
      sub_3F8(v93, "%s", (const char *)&v144); /*0x4b9a*/
      sub_EC(v94); /*0x4ba0*/
    }
    if ( !sub_2A8(&v144, *(_DWORD *)(v139 + 12) + 120) || !sub_134(&v144) ) /*0x4bb8*/
    {
      sub_B0(v150, 256); /*0x4bc8*/
      sub_BC(v150, "%s%s", v91); /*0x4bd8*/
      if ( !sub_D4(v150, 0) ) /*0x4be0*/
        sub_404(v150); /*0x4bea*/
    }
    v2 = v140; /*0x4bfc*/
    MEMORY[0x77248] = "hn"; /*0x4c02*/
    MEMORY[0x7724C] = "(Landroid/content/Context;Landroid/app/Application;)V"; /*0x4c02*/
    MEMORY[0x77250] = &loc_9CE4; /*0x4c08*/
    sub_A5C0(v140, "com/secneo/apkwrapper/AW", 0x77248u); /*0x4c16*/
    LODWORD(v95) = "()V"; /*0x4c1e*/
    HIDWORD(v95) = sub_A600; /*0x4c20*/
    MEMORY[0x77258] = v95; /*0x4c22*/
    MEMORY[0x77254] = "pn"; /*0x4c2c*/
    sub_A5C0(v2, "com/secneo/apkwrapper/AW", 0x77254u); /*0x4c32*/
    MEMORY[0x77260] = "d"; /*0x4c38*/
    LODWORD(v96) = "(Ljava/lang/String;)Ljava/lang/String;"; /*0x4c42*/
    HIDWORD(v96) = &loc_AD24; /*0x4c44*/
    MEMORY[0x77264] = v96; /*0x4c46*/
    sub_A5C0(v2, "com/secneo/apkwrapper/H", 0x77260u); /*0x4c50*/
    ((void (__fastcall *)(_DWORD *))loc_5074)(v140); /*0x4c54*/
    v97 = *(int **)(v139 + 12); /*0x4c5a*/
    v98 = *v97; /*0x4c5c*/
    v128 = v97[6] == 0; /*0x4c62*/
    v1 = 0x77158u; /*0x4c64*/
    MEMORY[0x77180] = *v97; /*0x4c66*/
    if ( !v128 ) /*0x4c6c*/
    {
      if ( *(_BYTE *)(MEMORY[0x6EE5C] + 2) == 49 ) /*0x4c74*/
      {
        v99 = ((int (__fastcall *)(const char *, __int64 *, _DWORD, int, _DWORD))loc_1FFBC)( /*0x4c88*/
                "libDexHelper.so",
                &v144,
                0,
                1,
                0);
        v1 = v144; /*0x4c8c*/
        v100 = sub_1542E(v99); /*0x4c94*/
        sub_54518(v1, v100); /*0x4c9a*/
        v102 = v101; /*0x4ca2*/
        v103 = sub_54454(v1 + 63, v100); /*0x4ca6*/
        sub_410(v1 - v102, (v103 + 1) * v100 - (v1 - v102), 3); /*0x4cb6*/
        v104 = MEMORY[0x6EE60]; /*0x4cc2*/
        *(_DWORD *)v1 = MEMORY[0x6EE64]; /*0x4cc6*/
        *(_DWORD *)(v1 + 4) = v104; /*0x4cc6*/
        *(_DWORD *)(v144 + 8) = MEMORY[0x6EE68]; /*0x4cd4*/
      }
LABEL_145:
      v4 = 65540; /*0x4d98*/
      goto LABEL_146; /*0x4d98*/
    }
    v105 = (_BYTE *)MEMORY[0x6EE5C]; /*0x4cda*/
    v106 = (char *)MEMORY[0x6EE6C]; /*0x4ce2*/
    *(_BYTE *)(MEMORY[0x6EE5C] + 4) = 50; /*0x4ce4*/
    strcpy(v106, "Java_"); /*0x4ce8*/
    v107 = MEMORY[0x6EE70]; /*0x4cfa*/
    *MEMORY[0x6EE70] = *(_QWORD *)"JNI_OnLoad"; /*0x4cfc*/
    *(_DWORD *)(v107 + 7) = 6578543; /*0x4d00*/
    v108 = sub_254(52); /*0x4d06*/
    v109 = (int **)MEMORY[0x6EE74]; /*0x4d12*/
    *(_QWORD *)(v108 + 16) = 0; /*0x4d1a*/
    *(_QWORD *)(v108 + 24) = 0; /*0x4d1a*/
    *(_QWORD *)(v108 + 32) = 0; /*0x4d22*/
    *(_QWORD *)(v108 + 40) = 0; /*0x4d22*/
    *v109 = (int *)v108; /*0x4d28*/
    *(_QWORD *)v108 = 0; /*0x4d2c*/
    *(_QWORD *)(v108 + 8) = 0; /*0x4d2c*/
    *(_DWORD *)(v108 + 48) = 0; /*0x4d32*/
    if ( *v105 == 49 ) /*0x4d38*/
    {
      v110 = sub_1F6D8(); /*0x4d3a*/
      ((void (__fastcall *)(int))loc_1F758)(v110); /*0x4d3e*/
      v111 = *v109; /*0x4d46*/
      v112 = (*v109)[9]; /*0x4d4e*/
      if ( v112 ) /*0x4d52*/
      {
        v113 = MEMORY[0x6EE7C]; /*0x4d54*/
        if ( (v112 > MEMORY[0x6EE7C] || (unsigned int)v111[10] < MEMORY[0x6EE7C]) && *v111 ) /*0x4d62*/
          v113 = *v111; /*0x4d66*/
        if ( v112 <= MEMORY[0x6EE78] && (unsigned int)v111[10] >= MEMORY[0x6EE78] ) /*0x4d72*/
        {
          v2 = (_DWORD *)MEMORY[0x6EE78]; /*0x4ea8*/
          v1 = 0x77158u; /*0x4eaa*/
        }
        else
        {
          v2 = (_DWORD *)v111[1]; /*0x4d76*/
          v1 = 0x77158u; /*0x4d7a*/
          if ( !v2 ) /*0x4d80*/
            v2 = (_DWORD *)MEMORY[0x6EE78]; /*0x4d82*/
        }
      }
      else
      {
        v2 = (_DWORD *)MEMORY[0x6EE78]; /*0x4e2c*/
        v113 = MEMORY[0x6EE7C]; /*0x4e30*/
      }
      if ( v98 < 24 ) /*0x4eae*/
      {
        sub_428(v113, (char *)&loc_1FAB4 + 1, 0x77184u); /*0x4ece*/
        v4 = 65540; /*0x4ed2*/
      }
      else
      {
        v121 = v111[2]; /*0x4eb0*/
        v4 = 65540; /*0x4eb8*/
        if ( v121 ) /*0x4ebc*/
          sub_428(v121, (char *)&loc_1FAB4 + 1, 0x77184u); /*0x4ec0*/
        else
          sub_434(); /*0x4ed6*/
      }
      sub_428(v2, sub_1FEA8, 0x77188u); /*0x4ee4*/
    }
    else
    {
      if ( v105[1] != 49 ) /*0x4d8a*/
        goto LABEL_145; /*0x4d8a*/
      v114 = sub_1F6D8(); /*0x4d8c*/
      ((void (__fastcall *)(int))loc_1F758)(v114); /*0x4d90*/
      v4 = 65540; /*0x4d94*/
    }
    if ( v105[1] != 49 ) /*0x4eec*/
      goto LABEL_146; /*0x4eec*/
    v122 = 0; /*0x4ef4*/
    v138 = *v109; /*0x4ef8*/
    v2 = 0; /*0x4efa*/
    v123 = 0; /*0x4efe*/
    v139 = 0x77158u; /*0x4f00*/
    v124 = (*v109)[9] - 8; /*0x4f08*/
    v125 = 0; /*0x4f0c*/
    while ( 1 ) /*0x4f18*/
    {
      v126 = (int *)(v124 + 8); /*0x4f18*/
      if ( v124 + 8 >= (unsigned int)(*v109)[10] ) /*0x4f1e*/
        break; /*0x4f1e*/
      v127 = *v126; /*0x4f20*/
      v128 = *v126 == -509558777; /*0x4f24*/
      if ( *v126 != -509558777 ) /*0x4f26*/
        v128 = v127 == -382926704; /*0x4f2a*/
      if ( v128 || (v1 = -392429456, v127 == -392429456) ) /*0x4f56*/
      {
        v129 = *(_DWORD *)(v124 + 12); /*0x4f2e*/
        v1 = -486510270; /*0x4f30*/
        if ( v129 == -486510270 ) /*0x4f34*/
          goto LABEL_182; /*0x4f34*/
        v1 = -476024829; /*0x4f36*/
        if ( v129 == -476024829 ) /*0x4f3a*/
          goto LABEL_181; /*0x4f3a*/
        v1 = -442535916; /*0x4f3c*/
        if ( v129 == -442535916 ) /*0x4f40*/
        {
          v130 = *(_DWORD *)(v124 + 40); /*0x4f5a*/
          switch ( v130 ) /*0x4f60*/
          {
            case 322: /*0x4f60*/
LABEL_182:
              v123 = v124 + 8; /*0x4f6e*/
              break; /*0x4f70*/
            case 192: /*0x4f60*/
LABEL_183:
              v2 = (_DWORD *)v124; /*0x4f72*/
              break; /*0x4f72*/
            case 54: /*0x4f60*/
LABEL_181:
              v122 = v124 + 8; /*0x4f6a*/
              break;
          }
        }
        else
        {
          v1 = -476024640; /*0x4f42*/
          if ( v129 == -476024640 ) /*0x4f46*/
            goto LABEL_183; /*0x4f46*/
          v1 = -476024827; /*0x4f48*/
          if ( v129 == -476024827 ) /*0x4f4c*/
            v125 = v124 + 8; /*0x4f4e*/
        }
      }
      if ( v125 || (v125 = v123) != 0 ) /*0x4f78*/
      {
        v131 = v122 == 0; /*0x4f7a*/
        if ( v122 ) /*0x4f7e*/
          v131 = v2 == 0; /*0x4f80*/
        if ( !v131 ) /*0x4f84*/
          break; /*0x4f84*/
      }
      else
      {
        v125 = 0; /*0x4f8a*/
      }
      ++v124; /*0x4f86*/
    }
    v4 = 65540; /*0x4f8e*/
    if ( !v125 ) /*0x4f90*/
      goto LABEL_197; /*0x4f90*/
    v132 = v122 == 0; /*0x4f92*/
    if ( v122 ) /*0x4f96*/
      v132 = v2 == 0; /*0x4f98*/
    if ( v132 ) /*0x4f9c*/
    {
LABEL_197:
      v125 = v138[3]; /*0x4fa4*/
      v2 = (_DWORD *)v138[4]; /*0x4fa4*/
      v122 = v138[5]; /*0x4fa4*/
    }
    v133 = (void (__fastcall *)(int, int (*)(), unsigned int))MEMORY[0x6EE80]; /*0x4fb2*/
    MEMORY[0x6EE80](v125, (char *)&loc_20214 + 1, 0x7718Cu); /*0x4fba*/
    v133(v122, sub_202D4, 0x77190u); /*0x4fc6*/
    v133((int)v2, (int (*)())sub_2033C, 0x77194u); /*0x4fd2*/
LABEL_146:
    if ( *v3 != v153 ) /*0x4da4*/
    {
      sub_158(*v3 - v153); /*0x4db6*/
LABEL_149:
      v116 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 576))( /*0x4dba*/
               v3,
               v1,
               "sApp",
               "Landroid/app/Application;");
      v117 = (*(int (__fastcall **)(_DWORD *, int, int))(*v3 + 580))(v3, v1, v116); /*0x4dde*/
      if ( v117 ) /*0x4de0*/
      {
        v118 = v117; /*0x4de2*/
        v119 = (*(int (__fastcall **)(_DWORD *, const char *))(*v3 + 24))(v3, "android/app/Application"); /*0x4df2*/
        v120 = (*(int (__fastcall **)(_DWORD *, int, const char *, const char *))(*v3 + 132))( /*0x4e08*/
                 v3,
                 v119,
                 "getApplicationInfo",
                 "()Landroid/content/pm/ApplicationInfo;");
        v56 = sub_41C(v3, v118, v120); /*0x4e14*/
        if ( v119 ) /*0x4e1a*/
          (*(void (__fastcall **)(_DWORD *, int))(*v3 + 92))(v3, v119); /*0x4e28*/
      }
      else
      {
        v56 = 0; /*0x4e3a*/
      }
      continue; /*0x4e2a*/
    }
    return v4; /*0x4db4*/
  }
}
