/*
BlackMatter ransomware
*/

import "elf"

rule DarkSide_BM
{
    meta:
        author = "rivitna"
        family = "ransomware.darkside_blackmatter"
        description = "DarkSide/BlackMatter ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h1 = { 64 A1 30 00 00 00     // mov  eax, large fs:30h
                8B B0 A4 00 00 00     // mov  esi, [eax+0A4h]
                8B B8 A8 00 00 00     // mov  edi, [eax+0A8h]
                83 FE 05              // cmp  esi, 5
                75 05                 // jnz  short L1
                83 FF 01 }            // cmp  edi, 1

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (1 of ($h*))
        )
}

rule BlackMatter
{
    meta:
        author = "rivitna"
        family = "ransomware.blackmatter.windows"
        description = "BlackMatter ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 80 C6 61              // add  dh, 61h
                80 EE 61              // sub  dh, 61h
                C1 CA 0D              // ror  edx, 0Dh
                03 D0 }               // add  edx, eax
        $h1 = { 02 F1                 // add  dh, cl
                2A F1                 // sub  dh, cl
                B9 0D 00 00 00        // mov  ecx, 0Dh
                D3 CA                 // ror  edx, cl
                03 D0 }               // add  edx, eax
        $h2 = { 3C 2B                 // cmp  al, 2Bh
                75 04                 // jnz  short L1
                B0 78                 // mov  al, 78h
                EB 0E                 // jnz  short L3
                                      // L1:
                3C 2F                 // cmp  al, 2Fh
                75 04                 // jnz  short L2
                B0 69                 // mov  al, 69h
                EB 06                 // jmp  short L3
                                      // L2:
                3C 3D                 // cmp  al, 3Dh
                75 02                 // jnz  short L3
                B0 7A }               // mov  al, 7Ah
                                      // L3:
        $h3 = { 33 C0                 // xor  eax, eax
                40                    // inc  eax
                40                    // inc  eax
                8D 0C C5 01 00 00 00  // lea  ecx, [eax*8+1]
                83 7D 0? 00           // cmp  [ebp+arg_0], 0
                75 04                 // jnz  short L1
                F7 D8                 // neg  eax
                EB 0? }               // jmp  short L2
                                      // L1:

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (1 of ($h*))
        )
}

rule BlackMatter_Linux
{
    meta:
        author = "rivitna"
        family = "ransomware.blackmatter.linux"
        description = "BlackMatter ransomware Linux payload"
        severity = 10
        score = 100

    strings:
        $h0 = {                       // Loop:
                0F B6 10              // movzx edx, byte ptr [rax]
                84 D2                 // test  dl, dl
                74 19                 // jz    L1
                0F B6 34 0F           // movzx esi, byte ptr [rdi+rcx]
                40 38 F2              // cmp   dl, sil
                74 10                 // jz    L1
                48 83 C1 01           // add   rcx, 1
                31 F2                 // xor   edx, esi
                48 83 F9 20           // cmp   rcx, 20h
                88 10                 // mov   [rax], dl
                49 0F 44 C9           // cmovz rcx, r9
                                      // L1:
                48 83 C0 01           // add   rax, 1
                4C 39 C0              // cmp   rax, r8
                75 D7 }               // jnz   Loop
        $h1 = { 44 42 46 44               // mov   [rsp+var_1], 44464244h
                C7 4? [1-2] 30 35 35 43   // mov   [rsp+var_2], 43353530h
                C7 4? [1-2] 2D 39 43 46   // mov   [rsp+var_3], 4643392Dh
                C7 4? [1-2] 32 2D 34 42   // mov   [rsp+var_4], 42342D32h
                C7 4? [1-2] 42 38 2D 39   // mov   [rsp+var_5], 392D3842h
                C7 4? [1-2] 30 38 45 2D   // mov   [rsp+var_6], 2D453830h
                C7 4? [1-2] 36 44 41 32   // mov   [rsp+var_7], 32414436h
                C7 4? [1-2] 32 33 32 31   // mov   [rsp+var_8], 31323332h
                C7 4? [1-2] 42 46 31 37 } // mov   [rsp+var_9], 37314642h


    condition:
        (uint32(0) == 0x464C457F) and
        (
            (1 of ($h*)) or
            for any i in (0..elf.number_of_sections-2):
            (
                (elf.sections[i].name == ".app.version") and
                (elf.sections[i+1].name == ".cfgETD")
            )
        )
}
