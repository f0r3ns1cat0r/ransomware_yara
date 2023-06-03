/*
Akira ransomware
*/


rule Akira
{
    meta:
        author = "rivitna"
        family = "ransomware.akira.windows"
        description = "Akira ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "\x00--encryption_path\x00" ascii
        $s1 = "\x00--share_file\x00" ascii
        $s2 = "\x00--encryption_percent\x00" ascii
        $s3 = "\x00Failed to read share files\x00" ascii
        $s4 = ":\\akira\\asio\\include\\" ascii
        $s5 = "\x00write_encrypt_info error: \x00" ascii
        $s6 = "\x00encrypt_part error: \x00" ascii
        $s7 = "\x00Trend Micro\x00" wide
        $s8 = " :Failed to make full encrypt\x00" wide
        $s9 = " :Failed to make spot encrypt\x00" wide
        $s10 = " :Failed to make part encrypt\x00" wide
        $s11 = " :Failed to write header\x00" wide
        $s12 = " :file rename failed. System error: \x00" wide

        $h0 = { 41 BA 05 00 00 00 41 80 FB 32 44 0F 42 D0 33 D2 48 8B C?
                49 F7 F2 4C 8B C8 B9 02 00 00 00 41 B8 04 00 00 00
                41 80 FB 32 44 0F 42 C1 41 8B C8 48 0F AF C8 48 2B F9 33 D2
                48 8B C7 49 F7 F2 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (7 of ($s*)) or
            (1 of ($h*))
        )
}