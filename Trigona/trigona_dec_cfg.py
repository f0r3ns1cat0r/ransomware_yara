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

import hashlib
from Crypto.Cipher import AES


# AES-256 CBC
AES_BLOCK_SIZE = 16
KEY_SIZE = 32
IV_SIZE = AES_BLOCK_SIZE

HASH_SIZE = 16


def decrypt_aes_cbc(enc_data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data (AES CBC)"""

    enc_data_size = len(enc_data)
    rem_size = enc_data_size % AES_BLOCK_SIZE
    block_size = enc_data_size - rem_size

    cv = iv

    data = b''

    if block_size != 0:
        cipher = AES.new(key, AES.MODE_CBC, cv)
        data = cipher.decrypt(enc_data[:block_size])
        cv = enc_data[block_size - AES_BLOCK_SIZE : block_size]

    if rem_size != 0:
        cipher = AES.new(key, AES.MODE_ECB)
        cv = cipher.encrypt(cv)
        last_block = bytearray(enc_data[block_size:])
        for i in range(rem_size):
            last_block[i] ^= cv[i]
        data += bytes(last_block)

    return data


def decrypt_cfg_data(enc_data: bytes) -> bytes:
    """Decrypt configuration data"""

    # Decrypt stage #1
    key = enc_data[:KEY_SIZE]
    iv = enc_data[KEY_SIZE : KEY_SIZE + IV_SIZE]
    enc_data = enc_data[KEY_SIZE + IV_SIZE:]
    enc_data = decrypt_aes_cbc(enc_data, key, iv)

    # Decrypt stage #2
    iv = enc_data[:IV_SIZE]
    key = enc_data[IV_SIZE : IV_SIZE + KEY_SIZE]
    enc_data = enc_data[KEY_SIZE + IV_SIZE:]
    data = decrypt_aes_cbc(enc_data, key, iv)

    if not data:
        return None

    # Check configuration data
    noise_data_size = data[0]
    cfg_pos = 1 + noise_data_size + HASH_SIZE
    if len(data) < cfg_pos:
        return None

    cfg_data = data[cfg_pos:]

    h = data[1 + noise_data_size : cfg_pos]
    if h != hashlib.md5(cfg_data).digest():
        return None

    return cfg_data


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io

    if len(sys.argv) != 2:
        print('Usage:', sys.argv[0], 'filename')
        sys.exit(0)

    filename = sys.argv[1]
    with io.open(filename, 'rb') as f:
        data = f.read()

    cfg_data = decrypt_cfg_data(data)
    if not cfg_data:
        print('Error: Failed to decrypt configuration data.')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(cfg_data)

    print('Done!')
