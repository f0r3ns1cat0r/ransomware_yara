# MIT License
#
# Copyright (c) 2023-2024 Andrey Zhdanov (rivitna)
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
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import chacha


# RSA
RSA_KEY_SIZE = 256

# ChaCha20/8
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 8
CHACHA_ROUNDS = 8

# Metadata
ENC_MARKER = b'\x66\x11\x61\x66'

METADATA_SIZE = RSA_KEY_SIZE + 4 + len(ENC_MARKER)


BLOCK_SIZE = 0x10000


SENTINEL_SIZE = 16


def rsa_construct_blob(blob):
    """Construct RSA key from BLOB"""

    is_private = False

    type_ver, key_alg, magic, key_bitlen = struct.unpack_from('<4L', blob, 0)
    # "RSA2"
    if (type_ver == 0x207) and (key_alg == 0xA400) and (magic == 0x32415352):
        is_private = True
    # "RSA1"
    elif (type_ver != 0x206) or (key_alg != 0xA400) or (magic != 0x31415352):
        raise ValueError('Invalid RSA blob')

    pos = 16
    key_len = math.ceil(key_bitlen / 8)

    e = int.from_bytes(blob[pos : pos + 4], byteorder='little')
    pos += 4
    n = int.from_bytes(blob[pos : pos + key_len], byteorder='little')

    if not is_private:
        return RSA.construct((n, e))

    key_len2 = math.ceil(key_bitlen / 16)

    pos += key_len
    p = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    q = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    dp = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    dq = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    iq = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    d = int.from_bytes(blob[pos : pos + key_len], byteorder='little')

    if (dp != d % (p - 1)) or (dq != d % (q - 1)):
        raise ValueError('Invalid RSA blob')

    return RSA.construct((n, e, d, p, q))


def decrypt_file(filename, priv_key):
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Check metadata marker
        if metadata[-len(ENC_MARKER):] != ENC_MARKER:
            return False

        # Decrypt ChaCha20 key and nonce
        cipher = PKCS1_v1_5.new(priv_key)

        sentinel = os.urandom(SENTINEL_SIZE)
        enc_key_data = metadata[:RSA_KEY_SIZE]
        key_data = cipher.decrypt(enc_key_data[::-1], sentinel)
        if key_data == sentinel:
            return False

        key = key_data[:CHACHA_KEY_SIZE]
        nonce = key_data[CHACHA_KEY_SIZE :
                         CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE]

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        cipher = chacha.ChaCha(key, nonce, 0, CHACHA_ROUNDS)

        f.seek(0)

        while True:

            enc_data = f.read(BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(-len(enc_data), 1)
            f.write(data)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read RSA private key BLOB
with io.open('./private.bin', 'rb') as f:
    priv_key_blob = f.read()

# Get RSA private key from BLOB
priv_key = rsa_construct_blob(priv_key_blob)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

# Copy file
new_filename = filename + '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
