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
import os
import io
import chacha


#CFG_POS = 0xCC00
CFG_POS = 0xD200
CFG_SIZE = 0x4E65

KEY_SIZE = 32
NONCE_SIZE = 12
CHACHA_ROUNDS = 20

SKIP_SIZE = 20


def decrypt_cfg_data(enc_data: bytes, key: bytes, nonce: bytes):
    """Decrypt configuration data"""

    # Change ChaCha20 constants
    #chacha.ChaCha.constants = [0, 0, 0, 0]
    # ChaCha20/8 decrypt
    cipher = chacha.ChaCha(key, nonce, 0, CHACHA_ROUNDS)
    return cipher.decrypt(enc_data)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    f.seek(CFG_POS)
    key = f.read(KEY_SIZE)
    nonce = f.read(NONCE_SIZE)
    f.seek(SKIP_SIZE, 1)
    enc_cfg_data = f.read(CFG_SIZE)

# Decrypt configuration data
data = decrypt_cfg_data(enc_cfg_data, key, nonce)

new_filename = filename + '.cfg'
with io.open(new_filename, 'wb') as f:
    f.write(data)
