/*
Qilin ransomware
*/

import "pe"


rule Qilin_Loader
{
    meta:
        author = "rivitna"
        family = "ransomware.qilin.windows"
        description = "Qilin ransomware Windows loader"
        severity = 10
        score = 100

    strings:
        $h0 = { 85 C0 75 12 E8 [4] 85 C0 0F 84 ?? 0? 00 00 A3 [4]
                68 00 ?? ( 2? | 3? | 4? ) 00 6A 00 50 E8 [4] 85 C0
                0F 84 ?? 0? 00 00 31 D2 BF 00 [2] FF ( BB | 8D ) [0-8]
                ( 89 44 24 ?? C7 44 24 ?? ?0 ?? ?? 00
                  C7 44 24 ?? 00 00 00 00 |
                  ( 89 45 ?? C7 45 ?? ?0 ?? ?? 00 |
                    C7 45 ?? ?0 ?? ?? 00 89 45 ?? )
                  C7 45 ?? 00 00 00 00 )
                EB }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        for any i in (0..pe.number_of_sections-1):
        (
            (pe.sections[i].raw_data_size >= 0x2A0000) and
            (pe.sections[i].raw_data_size <= 0x500000) and
            (pe.sections[i].name == ".rdata")
        ) and
        (1 of ($h*))
}
