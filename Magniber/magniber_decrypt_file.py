# MIT License
#
# Copyright (c) 2024 Andrey Zhdanov (rivitna)
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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES


RANSOM_EXT = '.xxxxxx'

RANSOM_DELIM = '_'


# RSA
RSA_KEY_SIZE = 256

# AES CBC
KEY_SIZE = 32
IV_SIZE = 16


# Metadata
METADATA_SIZE = RSA_KEY_SIZE


ENC_BLOCK_SIZE = 0x100000


SENTINEL_SIZE = 16


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA decrypt data"""

    key = RSA.import_key(priv_key_data)
    sentinel = os.urandom(SENTINEL_SIZE)
    cipher = PKCS1_v1_5.new(key)
    try:
        data = cipher.decrypt(enc_data[::-1], sentinel)
    except ValueError:
        return None
    if data == sentinel:
        return None
    return data


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Decrypt AES CBC key and IV
        enc_key_data = metadata[:RSA_KEY_SIZE]
        key_data = rsa_decrypt(enc_key_data, priv_key_data)
        if not key_data:
            return False

        key = key_data[:KEY_SIZE]
        iv = bytes([key_data[2 * i] for i in range(IV_SIZE)])
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        # Decrypt data
        f.seek(0)

        padding_size = 0

        eof = False

        while not eof:

            enc_data = f.read(ENC_BLOCK_SIZE)
            bytes_read = len(enc_data)
            if bytes_read != ENC_BLOCK_SIZE:
                eof = True
                if bytes_read == 0:
                    break

            data = cipher.decrypt(enc_data)

            if eof:
                # PKCS #5 padding
                padding_size = data[-1]
                if not 1 <= padding_size <= 16:
                    padding_size = 0

            f.seek(-bytes_read, 1)
            f.write(data)

        # Remove PKCS #5 padding
        if padding_size != 0:
            f.seek(-padding_size, 2)
            f.truncate()

        return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read RSA private key
with io.open('./rsa_privkey.bin', 'rb') as f:
    priv_key_data = f.read()

# Get original file name
new_filename = None

dirpath, enc_fname = os.path.split(filename)
if enc_fname.endswith(RANSOM_EXT):
    enc_fname = enc_fname[:-len(RANSOM_EXT)]
    pos = enc_fname.rfind(RANSOM_DELIM)
    if pos >= 0:
        fname = (enc_fname[:pos] + '.' + enc_fname[pos + len(RANSOM_DELIM):])
        new_filename = os.path.join(dirpath, fname)

if not new_filename:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
