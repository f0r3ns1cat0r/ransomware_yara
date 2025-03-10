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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20


RANSOM_EXT = '.xxxxxxxxxx'


# Encryption marker
ENC_MARKER = b'-----END CIPHERTEXT BLOCK-----'
ENC_MARKER_SIZE = len(ENC_MARKER) + 8


# RSA
RSA_KEY_SIZE = 512

# AES / ChaCha20
KEY_SIZE = 32
NONCE_SIZE = 16
CHACHA_NONCE_SIZE = 12


# Metadata
METADATA_SIZE = RSA_KEY_SIZE
VALUE_NOT_USED = 0xFFFFFFFFFFFFFFFF


ENC_BLOCK_SIZE = 0x80000


def is_file_encrypted(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        # Read marker
        try:
            f.seek(-ENC_MARKER_SIZE, 2)
        except OSError:
            return False

        marker = f.read()

    return marker[8:] == ENC_MARKER


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA OAEP decrypt data"""

    key = RSA.import_key(priv_key_data)
    decryptor = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        except OSError:
            return False

        enc_metadata = f.read(METADATA_SIZE)

        # Decrypt metadata
        metadata = rsa_decrypt(enc_metadata, priv_key_data)
        if metadata is None:
            return False

        # Parse metadata
        # AES/ChaCha20 key and nonce
        key = metadata[:KEY_SIZE]
        nonce = metadata[KEY_SIZE : KEY_SIZE + NONCE_SIZE]
        # Chunk size, chunk space
        chunk_size, chunk_space = struct.unpack_from('<2Q', metadata,
                                                     KEY_SIZE + NONCE_SIZE)
        # Encryption algorithm (0 - ChaCha20, 1 - AES CTR)
        enc_alg = metadata[KEY_SIZE + NONCE_SIZE + 16]

        # Decrypt data
        if enc_alg != 0:
            # AES CTR
            init_val = int.from_bytes(nonce, byteorder='little')
            counter = Counter.new(128, initial_value=init_val,
                                  little_endian=True)
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        else:
            # ChaCha20
            cipher = ChaCha20.new(key=key, nonce=nonce[:CHACHA_NONCE_SIZE])

        # Remove metadata
        f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        f.truncate()

        # Decrypt chunks
        pos = 0

        while True:

            # Decrypt chunk
            p = pos
            size = chunk_size
            while size != 0:

                block_size = min(size, ENC_BLOCK_SIZE)
                f.seek(p)
                enc_data = f.read(block_size)
                if enc_data == b'':
                    break

                dec_data = cipher.decrypt(enc_data)

                f.seek(p)
                f.write(dec_data)

                size -= block_size
                p += block_size

            else:
                if chunk_space != VALUE_NOT_USED:
                    pos += chunk_size + chunk_space
                    continue

            break

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Check if file is encrypted
if not is_file_encrypted(filename):
    print('Error: The file is damaged or not encrypted')
    sys.exit(1)

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
enc_count = 1

while True:

    if not decrypt_file(new_filename, priv_key_data):
        os.remove(new_filename)
        print('Error: Failed to decrypt file')
        sys.exit(1)

    # Check if file is encrypted
    if not is_file_encrypted(new_filename):
        break

    enc_count += 1
    print('Decryption #' + str(enc_count))
