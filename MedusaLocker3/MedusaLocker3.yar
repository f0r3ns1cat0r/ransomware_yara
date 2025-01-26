/*
MedusaLocker3 ransomware
*/


rule MedusaLocker3
{
    meta:
        author = "rivitna"
        family = "ransomware.medusalocker3"
        description = "MedusaLocker3 ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = { 50 55 54 49 4E 48 55 49 4C 4F 31 33 33 37 00 }
        $s1 = { 44 4F 4E 41 4C 44 54 52 55 4D 50 00 }
        $s2 = "\x00SETTINGS\x00" wide
        $s3 = "hiperDrives\x00" ascii
        $s4 = "ncryptedFileExtension\x00" ascii
        $s5 = "taskkill /f /im explorer.exe" wide
        $s6 = "\x00\\SysWOW64\\cmd.exe /c %windir%\\sysnative\\cmd.exe /c \x00" wide
        $s7 = "\x00:\\$Windows.~WS\\\x00" wide
        $s8 = "\x00[-] Run sync command: %s\n" wide
        $s9 = "\x00[!] Failed to run async command: %s" wide
        $s10 = "\x00[-] Get resource with id " wide
        $s11 = "\x00SOFTWARE\\PAIDMEMES\x00" wide
        $s12 = "\x00BabyLockerKZ\x00" wide
        $s13 = "\x00[+] Program added to autostart successfully." wide
        $s14 = "\x00[!] WNetGetConnection failed" wide

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (5 of ($s*))
        )
}
