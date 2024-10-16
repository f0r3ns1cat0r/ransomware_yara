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
import struct
import math
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import chacha


RSA_KEY_SIZE = 256
RSA_PRIV_KEY_BLOB_SIZE = 1172
CHACHA_ROUNDS = 8


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


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    data = base64.b64decode(f.read())

with io.open('./private_master.bin', 'rb') as f:
    master_key_blob = f.read()

master_priv_key = rsa_construct_blob(master_key_blob)

# Parse Maze key data
pos = RSA_PRIV_KEY_BLOB_SIZE

# Encrypted RSA private key data
enc_priv_key_blob = data[:pos]

# Encrypted ChaCha20 key and nonce
enc_chacha_key = data[pos : pos + RSA_KEY_SIZE]
pos += RSA_KEY_SIZE
enc_chacha_nonce = data[pos : pos + RSA_KEY_SIZE]
pos += RSA_KEY_SIZE

# Decrypt ChaCha20 key and nonce
cipher = PKCS1_v1_5.new(master_priv_key)

sentinel = os.urandom(SENTINEL_SIZE)
chacha_key = cipher.decrypt(enc_chacha_key[::-1], sentinel)
if chacha_key == sentinel:
    print('Failed to decrypt ChaCha20 key')
    sys.exit(1)

print('ChaCha20 key size:', len(chacha_key))

sentinel = os.urandom(SENTINEL_SIZE)
chacha_nonce = cipher.decrypt(enc_chacha_nonce[::-1], sentinel)
if chacha_nonce == sentinel:
    print('Failed to decrypt ChaCha20 nonce')
    sys.exit(1)

print('ChaCha20 nonce size:', len(chacha_nonce))

# Decrypt RSA private key BLOB
cipher = chacha.ChaCha(chacha_key, chacha_nonce, 0, CHACHA_ROUNDS)
priv_key_blob = cipher.decrypt(enc_priv_key_blob)

priv_key = rsa_construct_blob(priv_key_blob)

print('Private RSA key size:', priv_key.size_in_bits())

with io.open('./private.bin', 'wb') as f:
    f.write(priv_key_blob)
