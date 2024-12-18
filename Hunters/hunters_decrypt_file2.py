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
import os
import io
import shutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Crypto.Cipher import AES
from Crypto.Util import Counter


RANSOM_EXT = '.locked'


# RSA
RSA_KEY_SIZE = 0x280


# AES
NUM_KEYS = 10
KEY_SIZE = 32
NONCE_SIZE = 16
KEY_DATA_SIZE = KEY_SIZE + NONCE_SIZE


# Footer
FOOTER_SIZE = RSA_KEY_SIZE


BLOCK_SIZE = 0x80000


KEY_BLOCK_SIZE = 0x200


def is_file_encrypted(filename: str,
                      enc_marker: bytes, enc_marker_pos: int) -> bool:
    """Check if file is encrypted"""

    enc_marker_size = len(enc_marker)

    with io.open(filename, 'rb') as f:
        f.seek(enc_marker_pos)
        marker = f.read(enc_marker_size)

    if len(marker) != enc_marker_size:
        return False

    return marker[4:] == enc_marker[4:]


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(priv_key, hashAlgo=SHA3_512)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def prepare_decryptors(key_data: bytes) -> list:
    """Prepare decryptors"""

    decryptors = []

    for i in range (NUM_KEYS):
        # AES CTR
        key = key_data[i * KEY_DATA_SIZE : i * KEY_DATA_SIZE + KEY_SIZE]
        iv = key_data[i * KEY_DATA_SIZE + KEY_SIZE:
                      i * KEY_DATA_SIZE + KEY_SIZE + NONCE_SIZE]
        init_val = int.from_bytes(iv, byteorder='little')
        counter = Counter.new(128, initial_value=init_val,
                              little_endian=True)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        decryptors.append(cipher)

    return decryptors


def get_enc_chunks(enc_mode: int, data_size: int) -> list:
    """Get encryption chunks"""

    if (enc_mode == 1) or (enc_mode == 6) or (enc_mode == 7):
        return [(False, data_size)]

    chunks = []

    if (enc_mode == 2) or (enc_mode == 3) or (enc_mode == 8):

        if enc_mode != 8:
            first_chunk_percent = 10
            rest_enc_percent = 20
            num_rest_chunks = 5
        else:
            first_chunk_percent = 30
            rest_enc_percent = 10
            num_rest_chunks = 10

        first_chunk_size = (data_size * first_chunk_percent) // 100
        rest_enc_size = (data_size * rest_enc_percent) // 100
        enc_size = first_chunk_size + rest_enc_size
        chunk_size, chunk_rem = divmod(rest_enc_size, num_rest_chunks)
        space_size, space_rem = divmod(data_size - enc_size, num_rest_chunks)

        first_space_size = space_size + space_rem
        second_chunk_size = chunk_size + chunk_rem

    elif (enc_mode == 4) or (enc_mode == 5):

        first_chunk_percent = 5
        chunk_size = 0x100000
        if enc_mode == 4:
            first_enc_chunk_max_size = 0xA00000
            rest_enc_percent = 45
            max_num_rest_chunks = 50
        else:
            first_enc_chunk_max_size = 0x6400000
            rest_enc_percent = 50
            max_num_rest_chunks = 150

        first_chunk_size = min(first_enc_chunk_max_size,
                               (data_size * first_chunk_percent) // 100)
        rest_data_size = data_size - first_chunk_size
        rest_enc_size = min(rest_data_size,
                            max(chunk_size,
                                (data_size * rest_enc_percent) // 100))
        num_rest_chunks = min(max_num_rest_chunks,
                              rest_enc_size // chunk_size)
        rest_enc_size = num_rest_chunks * chunk_size
        space_size, space_rem = divmod(rest_data_size - rest_enc_size,
                                       num_rest_chunks)

        first_space_size = space_size + space_rem
        second_chunk_size = chunk_size

    else:
        return None

    chunks.append((False, first_chunk_size))
    chunks.append((True, first_space_size))
    chunks.append((False, second_chunk_size))

    for i in range(num_rest_chunks - 1):
        chunks.append((True, space_size))
        chunks.append((False, chunk_size))

    return chunks


def decrypt_file(filename: str,
                 enc_marker: bytes, enc_marker_pos: int,
                 rsa_priv_keys: list[RSA.RsaKey]) -> bool:
    """Decrypt file data"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        enc_marker_size = len(enc_marker)
        enc_start_pos = enc_marker_pos + enc_marker_size

        if file_size < FOOTER_SIZE + enc_start_pos:
            return False

        orig_file_size = file_size - FOOTER_SIZE

        # Read footer
        f.seek(-FOOTER_SIZE, 2)
        footer_data = f.read(FOOTER_SIZE)

        # Decrypt metadata
        for rsa_priv_key in rsa_priv_keys:
            metadata = rsa_decrypt(footer_data, rsa_priv_key)
            if metadata:
                break
        else:
            return False

        # Parse metadata
        enc_offset = metadata[0]
        enc_mode = metadata[1]
        marker_orig_data = metadata[2 : 2 + enc_marker_size]
        key_data = metadata[2 + enc_marker_size:]

        enc_start_pos += enc_offset

        # Prepare decryptors
        decryptors = prepare_decryptors(key_data)

        # Get encryption chunks
        chunks = get_enc_chunks(enc_mode, orig_file_size - enc_start_pos)
        if not chunks:
            return False

        # Remove metadata
        f.truncate(orig_file_size)

        # Restore original data instead of the encryption marker
        f.seek(enc_marker_pos)
        f.write(marker_orig_data)

        # Decrypt data
        pos = enc_start_pos
        key_index = 0

        for (skip_chunk, chunk_size) in chunks:

            if not skip_chunk:

                f.seek(pos)

                eof = False
                size = chunk_size
                while not eof and (size != 0):

                    block_size = min(size, BLOCK_SIZE)
                    enc_data = f.read(block_size)
                    bytes_read = len(enc_data)
                    if bytes_read != block_size:
                        eof = True
                        if bytes_read == 0:
                            break

                    data = b''

                    for key_block in (enc_data[i : i + KEY_BLOCK_SIZE]
                                      for i in range(0, bytes_read,
                                                     KEY_BLOCK_SIZE)):
                        data += decryptors[key_index].decrypt(key_block)
                        key_index = (key_index + 1) % NUM_KEYS

                    f.seek(-bytes_read, 1)
                    f.write(data)

                    size -= bytes_read

                if eof:
                    break

            pos += chunk_size

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

rsa_priv_keys = []

# Read private RSA key DER data
with io.open('./rsa_privkey0.bin', 'rb') as f:
    rsa_priv_keys.append(RSA.import_key(f.read()))
with io.open('./rsa_privkey1.bin', 'rb') as f:
    rsa_priv_keys.append(RSA.import_key(f.read()))

# Read encryption marker positions
with io.open('./marker.txt', 'rt') as f:
    enc_marker_pos = int(f.read(), 16)

# Read encryption marker
with io.open('./marker.bin', 'rb') as f:
    enc_marker = f.read()

if len(enc_marker) <= 4:
    print('Error: Invalid encryption marker')

# Check if file is encrypted
if not is_file_encrypted(filename, enc_marker, enc_marker_pos):
    print('Error: The file is damaged or not encrypted')
    sys.exit(1)

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, enc_marker, enc_marker_pos, rsa_priv_keys):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
