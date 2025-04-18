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
from Crypto.Cipher import ChaCha20


RANSOM_EXT = '.locked'

# Encryption marker / Attacker ID (hardcoded in the sample)
ENC_MARKER = b'\xDC\xB8\xA7\xA5\xB6\x18\xD2\x96\xD3\xBA\x01\xD9\xF9\x03\x9F\xC0\x7A'
# Encryption marker file position (hardcoded in the sample)
ENC_MARKER_POS = 0x36

ENC_MARKER_SIZE = len(ENC_MARKER) + 4


RSA_KEY_SIZE = 0x280
METADATA_SIZE = RSA_KEY_SIZE

NUM_KEYS = 9
KEY_SIZE = 32
XCHACHA_NONCE_SIZE = 24
KEY_DATA_SIZE = KEY_SIZE + XCHACHA_NONCE_SIZE


# Small file max data size
SMALL_FILE_MAX_DATA_SIZE = 0x500000

# Big file
# First chunk percent
FIRST_ENC_CHUNK_PERCENT = 10
# First chunk max size
FIRST_ENC_CHUNK_MAX_SIZE = 0x6400000
# Rest encrypted data percent
REST_ENC_DATA_PERCENT = 5
# Rest encrypted data max size
REST_ENC_DATA_MAX_SIZE = 0x6400000

BLOCK_SIZE = 0x80000
KEY_BLOCK_SIZE = 0x200


def is_file_encrypted(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:
        f.seek(ENC_MARKER_POS)
        marker = f.read(ENC_MARKER_SIZE)

    if len(marker) != ENC_MARKER_SIZE:
        return False

    return marker[4:] == ENC_MARKER


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
        # XChaCha20
        key = key_data[i * KEY_DATA_SIZE : i * KEY_DATA_SIZE + KEY_SIZE]
        nonce = key_data[i * KEY_DATA_SIZE + KEY_SIZE:
                         i * KEY_DATA_SIZE + KEY_SIZE + XCHACHA_NONCE_SIZE]
        decryptors.append(ChaCha20.new(key=key, nonce=nonce))

    return decryptors


def get_enc_blocks(data_size: int) -> list:
    """Get encryption blocks"""

    blocks = []

    if data_size > SMALL_FILE_MAX_DATA_SIZE:
        # Big file

        # First chunk
        first_chunk_size = min(FIRST_ENC_CHUNK_MAX_SIZE,
                               (data_size * FIRST_ENC_CHUNK_PERCENT) // 100)
        num_blocks, last_block_size = divmod(first_chunk_size, BLOCK_SIZE)
        for _ in range(num_blocks):
            blocks.append((False, BLOCK_SIZE))
        if last_block_size != 0:
            blocks.append((False, last_block_size))

        rest_enc_data_size = min(REST_ENC_DATA_MAX_SIZE,
                                 (data_size * REST_ENC_DATA_PERCENT) // 100)

        enc_size = first_chunk_size + rest_enc_data_size
        space_size = data_size - enc_size

        if rest_enc_data_size >= BLOCK_SIZE:

            num_chunks, last_block_size = divmod(rest_enc_data_size,
                                                 BLOCK_SIZE)
            chunk_space = space_size // num_chunks

            for _ in range(num_chunks):
                blocks.append((True, chunk_space))
                blocks.append((False, BLOCK_SIZE))

            space_size -= num_chunks * chunk_space
            if space_size > 0:
                blocks.append((True, space_size))

        else:
            blocks.append((True, space_size))
            last_block_size = rest_enc_data_size

    else:
        # Small file
        num_blocks, last_block_size = divmod(data_size, BLOCK_SIZE)
        for _ in range(num_blocks):
            blocks.append((False, BLOCK_SIZE))

    if last_block_size != 0:
        blocks.append((False, last_block_size))

    return blocks


def decrypt_file(rsa_priv_keys: list, filename: bytes) -> bool:
    """Decrypt file data"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        enc_start_pos = ENC_MARKER_POS + ENC_MARKER_SIZE

        if file_size < METADATA_SIZE + ENC_MARKER_SIZE + enc_start_pos:
            return False

        orig_file_size = file_size - (METADATA_SIZE + ENC_MARKER_SIZE)

        # Read original data and metadata
        f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        metadata = f.read(METADATA_SIZE + ENC_MARKER_SIZE)
        orig_data = metadata[:ENC_MARKER_SIZE]
        metadata = metadata[ENC_MARKER_SIZE:]

        # Decrypt metadata
        for rsa_priv_key in rsa_priv_keys:
            key_data = rsa_decrypt(metadata, rsa_priv_key)
            if key_data is not None:
                break
        else:
            return False

        # Prepare decryptors
        decryptors = prepare_decryptors(key_data)

        # Remove metadata
        f.truncate(orig_file_size)

        # Restore original data
        f.seek(ENC_MARKER_POS)
        f.write(orig_data)

        # Get encryption blocks
        blocks = get_enc_blocks(orig_file_size - enc_start_pos)

        # Decrypt data
        pos = enc_start_pos
        key_index = 0

        for block in blocks:

            skip_block, block_size = block

            if not skip_block:

                f.seek(pos)
                enc_data = f.read(block_size)

                dec_data = b''

                for block in (enc_data[i : i + KEY_BLOCK_SIZE]
                              for i in range(0, len(enc_data), KEY_BLOCK_SIZE)):
                    dec_data += decryptors[key_index].decrypt(block)
                    key_index = (key_index + 1) % NUM_KEYS

                f.seek(pos)
                f.write(dec_data)

                if len(enc_data) < block_size:
                    break

            pos += block_size

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

# Check if file is encrypted
if not is_file_encrypted(filename):
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
if not decrypt_file(rsa_priv_keys, new_filename):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
