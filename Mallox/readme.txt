MalloxDecryptor
---------------

Supported types:

  mallox0  *.mallox (from October 2022 to March 2023)
  xollam0  *.xollam (January 2023)
  bitenc   *.bitenc (January 2023)
  malox    *.malox (from April 2023 to July 2023)
  maloxx   *.maloxx (Juny 2023)
  mallox1  *.mallox (August 2023)
  xollam1  *.xollam (August 2023)
  malloxx  *.malloxx (August 2023)
  mallab   *.mallab (from September 2023 to October 2023)
  mallox2  *.mallox (from November 2023 to February 2024)
  ma1x0    *.ma1x0 (February 2024)


1. Brute the decryption key.

To get the decryption key, first run the decryptor on the compromised computer (!!!):

decryptor.exe -brute <ENCFILE>

ENCFILE - any encrypted file.

If successfully, '*.key' will be created. You don't need to do this stage anymore.

!!! If Windows has been reinstalled or if the system disk has been formatted, the key can also be bruted. In this case write to me. !!!

!!! If you have become a victim of the "corporate" version of Mallox, also write to me. !!!


2. Decrypt files.

decryptor.exe -key <KEYFILE< [-all] [-r] [-d] [<PATH1>] [<PATH2>] ... [<PATHN>]

-key  Set key file (*.key)
-all  Scan all fixed and removable disks.
-r    Replace existing files.
-d    Delete encrypted files and ransom notes.

KEYFILE                       - key file name (*.key)
<PATH1>, <PATH2>, ... <PATHN> - paths to scan.
