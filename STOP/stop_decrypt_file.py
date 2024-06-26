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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import Salsa20


RANSOM_EXT = '.test'

ENC_MARKER = b'{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}'

# RSA
RSA_KEY_SIZE = 256

# Salsa20
SALSA_KEY_SIZE = 32
SALSA_NONCE_SIZE = 8

# Metadata
ENC_MARKER_SIZE = len(ENC_MARKER)
RSA_KEY_ID_SIZE = 40
METADATA_SIZE = RSA_KEY_SIZE + RSA_KEY_ID_SIZE

ENC_START_POS = 5
ENC_MAX_SIZE = 153600


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA OAEP decrypt data"""

    key = RSA.import_key(priv_key_data)
    decryptor = PKCS1_OAEP.new(key)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read marker
        try:
            f.seek(-ENC_MARKER_SIZE, 2)
        except OSError:
            return False

        marker = f.read(ENC_MARKER_SIZE)
        if marker != ENC_MARKER:
            return False

        # Read metadata
        try:
            f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)
        enc_key_data = metadata[:RSA_KEY_SIZE]
        rsa_key_id = metadata[RSA_KEY_SIZE:]

        # Decrypt UUID
        uuid = rsa_decrypt(enc_key_data, priv_key_data)
        if uuid is None:
            return False

        # Remove metadata
        f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        f.truncate()

        # Decrypt data
        key = uuid[:SALSA_KEY_SIZE]
        nonce = uuid[:SALSA_NONCE_SIZE]
        cipher = Salsa20.new(key, nonce)

        f.seek(0)
        enc_data = f.read(ENC_START_POS + ENC_MAX_SIZE)

        data = cipher.decrypt(enc_data[ENC_START_POS:])

        f.seek(ENC_START_POS)
        f.write(data)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey.pem', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
