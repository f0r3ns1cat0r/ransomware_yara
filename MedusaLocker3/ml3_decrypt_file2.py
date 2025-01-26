# MIT License
#
# Copyright (c) 2023-2025 Andrey Zhdanov (rivitna)
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
import shutil
import struct
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20
import ml3_crypt


RANSOM_EXT = '.xxxxxxxx'


# RSA
RSA_KEY_SIZE = 256

# ChaCha20
KEY_SIZE = 32
NONCE_SIZE = 8

# Footer
ENC_SESSION_RSA_KEY_SIZE = 5 * RSA_KEY_SIZE
FOOTER_SIZE = ENC_SESSION_RSA_KEY_SIZE + RSA_KEY_SIZE + 8


def decrypt_file(filename: str, priv_key: RSA.RsaKey,
                 is_master_key: bool = False) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < FOOTER_SIZE:
            return False

        # Read footer
        f.seek(-FOOTER_SIZE, 2)
        footer = f.read(FOOTER_SIZE)

        if is_master_key:
            # Decrypt session RSA private key
            enc_key_blob = footer[:ENC_SESSION_RSA_KEY_SIZE]
            s_priv_key_blob = ml3_crypt.decrypt_session_key(enc_key_blob,
                                                            priv_key)
            if not s_priv_key_blob:
                print('master RSA private key: Failed')
                return False

            # Get RSA private key from BLOB
            s_priv_key = ml3_crypt.rsa_construct_blob(s_priv_key_blob)
            if (s_priv_key is None) or not s_priv_key.has_private():
                print('master RSA private key: Failed')
                return False

            print('master RSA private key: OK')

        else:
            s_priv_key = priv_key

        # Decrypt ChaCha20 key
        enc_key_data = footer[ENC_SESSION_RSA_KEY_SIZE :
                              ENC_SESSION_RSA_KEY_SIZE + RSA_KEY_SIZE]
        key_data = ml3_crypt.rsa_decrypt(enc_key_data, s_priv_key)
        if not key_data:
            print('session RSA private key: Failed')
            return False

        print('session RSA private key: OK')

        orig_file_size = file_size - FOOTER_SIZE
        print('original file size:', orig_file_size)

        enc_size, block_size = \
            struct.unpack_from('<LL', footer,
                               ENC_SESSION_RSA_KEY_SIZE + RSA_KEY_SIZE)

        print('enc size: %08X' % enc_size)
        print('block size: %08X' % block_size)

        if enc_size > orig_file_size:
            enc_size = orig_file_size

        # Decrypt data
        key = key_data[:KEY_SIZE]
        nonce = key_data[KEY_SIZE : KEY_SIZE + NONCE_SIZE]
        cipher = ChaCha20.new(key=key, nonce=nonce)

        # Decrypt begin blocks
        pos = 0
        while pos < enc_size:

            f.seek(pos)
            enc_data = f.read(block_size)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(pos)
            f.write(data)

            pos += 2 * block_size

        if orig_file_size > 2 * enc_size:

            # Decrypt end blocks
            pos = orig_file_size - enc_size
            while pos < orig_file_size:

                f.seek(pos)
                enc_data = f.read(block_size)
                if enc_data == b'':
                    break

                data = cipher.decrypt(enc_data)

                f.seek(pos)
                f.write(data)

                pos += 2 * block_size

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

# Read master/session RSA private key BLOB
with io.open('./privkey.txt', 'rb') as f:
    priv_key_blob = base64.b64decode(f.read())

# Get RSA private key from BLOB
priv_key = ml3_crypt.rsa_construct_blob(priv_key_blob)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key, True):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
