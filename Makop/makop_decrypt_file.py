# MIT License
#
# Copyright (c) 2025 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import sys
import io
import os
import struct
import shutil
from binascii import crc32
from Crypto.Cipher import AES


RANSOM_EXT = '.xxxxxx'

RANSOM_SUFFIX_PREFIX = '.['
RANSOM_SUFFIX_POSTFIX = ']'


# RSA
RSA_KEY_SIZE = 128

# AES
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16


# Footer
ENC_MARKER = 0x21592EF3

FOOTER_METADATA_SIZE_POS = 0
FOOTER_IV_POS = FOOTER_METADATA_SIZE_POS + 4
FOOTER_IV_SIZE = AES_BLOCK_SIZE
FOOTER_ENCKEY_POS = FOOTER_IV_POS + FOOTER_IV_SIZE
FOOTER_ENCKEY_SIZE = RSA_KEY_SIZE
FOOTER_ATTACKER_ID_POS = FOOTER_ENCKEY_POS + FOOTER_ENCKEY_SIZE
FOOTER_ATTACKER_ID_SIZE = 4
FOOTER_MARKER_POS = FOOTER_ATTACKER_ID_POS + FOOTER_ATTACKER_ID_SIZE
FOOTER_MARKER_SIZE = 4
FOOTER_SIZE = FOOTER_MARKER_POS + FOOTER_MARKER_SIZE

# Metadata
METADATA_BLOCK_SIZE_POS = 0
METADATA_UNK2_POS = METADATA_BLOCK_SIZE_POS + 4
METADATA_UNK3_POS = METADATA_UNK2_POS + 4
METADATA_FILESIZE_POS = METADATA_UNK3_POS + 4
METADATA_FILENAME_SIZE_POS = METADATA_FILESIZE_POS + 8
METADATA_FILENAME_POS = METADATA_FILENAME_SIZE_POS + 4
METADATA_MIN_SIZE = 32


def decrypt_file(filename: str, aes_key: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read footer part
        try:
            f.seek(-FOOTER_SIZE, 2)
        except OSError:
            return False

        footer = f.read(FOOTER_SIZE)

        # Check encryption marker
        enc_marker, = struct.unpack_from('<L', footer, FOOTER_MARKER_POS)
        if enc_marker != ENC_MARKER:
            return False

        # Attacker ID
        attacker_id, = struct.unpack_from('<L', footer,
                                          FOOTER_ATTACKER_ID_POS)
        print('attacker id: %08X' % attacker_id)

        # Encrypted key data
        enc_key_data = footer[FOOTER_ENCKEY_POS:
                              FOOTER_ENCKEY_POS + FOOTER_ENCKEY_SIZE]

        # AES IV
        aes_iv = footer[FOOTER_IV_POS :  FOOTER_IV_POS + FOOTER_IV_SIZE]

        # Read metadata
        metadata_size, = struct.unpack_from('<L', footer,
                                            FOOTER_METADATA_SIZE_POS)
        if (metadata_size < METADATA_MIN_SIZE) or (metadata_size & 0xF != 0):
            return False

        footer_size = FOOTER_SIZE + metadata_size
        print('footer size:', footer_size)

        try:
            f.seek(-footer_size, 2)
        except OSError:
            return False
        
        enc_metadata = f.read(metadata_size)

        # Decrypt metadata
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        metadata = cipher.decrypt(enc_metadata)

        filename_size, = struct.unpack_from('<L', metadata,
                                            METADATA_FILENAME_SIZE_POS)

        # Check metadata size
        eff_metadata_size = METADATA_FILENAME_POS + filename_size
        if eff_metadata_size + 4 > metadata_size:
            return False

        # Check metadata checksum
        metadata_crc32, = struct.unpack_from('<L', metadata,
                                             eff_metadata_size)
        if metadata_crc32 != crc32(metadata[:eff_metadata_size]):
            return False

        print('metadata crc32: %08X' % metadata_crc32)

        block_size, unk2, unk3, orig_file_size = \
            struct.unpack_from('<3LQ', metadata, METADATA_BLOCK_SIZE_POS)

        orig_filename_data = metadata[METADATA_FILENAME_POS:
                                      METADATA_FILENAME_POS + filename_size]
        orig_filename = orig_filename_data.decode('UTF-16-LE')

        print('block size: %08X' % block_size)
        print('unk2: %08X' % unk2)
        print('unk3: %08X' % unk3)
        print('original file size:', orig_file_size)
        print('original file name: \"%s\"' % orig_filename)

        # Decrypt data
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)

        if block_size == 0:
            block_size = orig_file_size
            rem = orig_file_size % AES_BLOCK_SIZE
            if rem != 0:
                block_size += AES_BLOCK_SIZE - rem

        f.seek(0)
        enc_data = f.read(block_size)

        data = cipher.decrypt(enc_data)

        f.seek(0)
        f.write(data)

        # Remove footer
        f.truncate(orig_file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./aes_key.bin', 'rb') as f:
    aes_key = f.read(AES_KEY_SIZE)

new_filename = None

# Get original file name
if filename.endswith(RANSOM_SUFFIX_POSTFIX + RANSOM_EXT):
    pos = filename.rfind(RANSOM_SUFFIX_POSTFIX + RANSOM_SUFFIX_PREFIX)
    if pos > 0:
        pos = filename.rfind(RANSOM_SUFFIX_PREFIX, 0, pos)
        if pos > 0:
            new_filename = filename[:pos]

if not new_filename:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, aes_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
