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
import shutil
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import chacha


RANSOM_EXT = '.safepay'


# x25519
X25519_KEY_SIZE = 32

# AES / XChaCha20
KEY_SIZE = 32
IV_SIZE = 16
XNONCE_SIZE = chacha.XNONCE_SIZE


# Footer
FOOTER_FILESIZE_POS = 0
FOOTER_PUBKEY_POS = 8
FOOTER_SPUBKEY_POS = FOOTER_PUBKEY_POS + X25519_KEY_SIZE
FOOTER_CHUNKSIZE_POS = FOOTER_SPUBKEY_POS + X25519_KEY_SIZE
FOOTER_ALG_POS = FOOTER_CHUNKSIZE_POS + 1
FOOTER_SIZE = FOOTER_ALG_POS + 1 + 6


BLOCK_SIZE = 0x100000
CHUNK_STEP = 10


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read footer
        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < FOOTER_SIZE:
            return False

        file_size -= FOOTER_SIZE

        # Read footer
        f.seek(file_size)
        footer_data = f.read(FOOTER_SIZE)

        orig_file_size, = struct.unpack_from('<Q', footer_data,
                                             FOOTER_FILESIZE_POS)
        print('original file size:', orig_file_size)

        blocks_per_chunk = footer_data[FOOTER_CHUNKSIZE_POS]
        print('blocks per chunk:', blocks_per_chunk)

        # Encryption algorithm
        alg = footer_data[FOOTER_ALG_POS]
        print('algorithm:', 'AES' if alg == 0 else 'XChaCha20')

        priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)

        # Check public key
        pub_key = priv_key.public_key()
        pub_key_data = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_key_data2 = footer_data[FOOTER_PUBKEY_POS:
                                    FOOTER_PUBKEY_POS + X25519_KEY_SIZE]
        if pub_key_data != pub_key_data2:
            print('X25519 private key: Failed')
            return False

        print('X25519 private key: OK')

        # Derive x25519 shared secret
        spub_key_data = footer_data[FOOTER_SPUBKEY_POS:
                                    FOOTER_SPUBKEY_POS + X25519_KEY_SIZE]
        spub_key = X25519PublicKey.from_public_bytes(spub_key_data)
        shared_secret = priv_key.exchange(spub_key)

        # Derive encryption key
        key_data = hashlib.sha512(shared_secret).digest()
        key = key_data[:KEY_SIZE]

        # Decrypt data
        if alg == 0:
            # AES-256 CBC
            iv = key_data[KEY_SIZE : KEY_SIZE + IV_SIZE]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
        else:
            # XChaCha20
            xnonce = bytearray(key_data[KEY_SIZE : KEY_SIZE + XNONCE_SIZE])

        block_space = (CHUNK_STEP - blocks_per_chunk) * BLOCK_SIZE

        pos = 0

        while pos < file_size:

            # Decrypt chunk
            for i in range(blocks_per_chunk):

                # Read block
                block_size = min(file_size - pos, BLOCK_SIZE)
                f.seek(pos)
                enc_data = f.read(block_size)
                bytes_read = len(enc_data)
                if bytes_read == 0:
                    break

                # Decrypt block
                if alg == 0:
                    # AES-256 CBC
                    data = decryptor.update(enc_data)
                else:
                    # XChaCha20
                    xkey = chacha.hchacha(key, xnonce[:chacha.HNONCE_SIZE])
                    nonce = b'\0' * 8 + xnonce[chacha.HNONCE_SIZE:]
                    cipher = Cipher(algorithms.ChaCha20(xkey, nonce), mode=None)
                    decryptor = cipher.decryptor()
                    data = decryptor.update(enc_data)

                    # Update XChaCha20 nonce
                    n = 1
                    for i in range(XNONCE_SIZE):
                        n += xnonce[i]
                        xnonce[i] = n & 0xFF
                        n >>= 8

                # Write block
                f.seek(pos)
                f.write(data)

                pos += BLOCK_SIZE

            pos += block_space

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

with io.open('./privkey.bin', 'rb') as f:
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
