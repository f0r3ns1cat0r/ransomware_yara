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
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
import xxhash32


RANSOM_EXT = '.PLAY'


# Metadata
RSA_KEY_SIZE = 1024

ENC_KEY_DATA_POS = 40

METADATA_SIZE = ENC_KEY_DATA_POS + RSA_KEY_SIZE

ENC_MARKER_SIZE = 16
ENC_MARKER_HASH_POS = 28
NUM_BLOCKS_POS = 32

# AES Key BLOB
AES_KEY_BLOB_SIZE = 0x230
AES_KEY_POS = 0x18

AES_BLOCK_SIZE = 16
AES_IV_SIZE = 16
AES_GCM_NONCE_SIZE = 12


MIN_ENC_FILE_SIZE = METADATA_SIZE + 16
MIN_ENC2_FILE_SIZE = MIN_ENC_FILE_SIZE + RSA_KEY_SIZE
SMALL_FILE_MAX_SIZE = 16711680


SENTINEL_SIZE = 16


def mod_inverse(a: int, m: int) -> int:
    """
    Calculate the modular inverse of a % m, which is the number x such that
    a * x % m = 1
    """

    # Get GCD of a and m using Euclidean Algorithm
    x = a
    y = m
    while x != 0:
        x, y = y % x, x
    if y != 1:
        return None

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = \
            (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def get_rsa_key_from_blob(blob: bytes) -> RSA.RsaKey:
    """Get RSA key from BLOB"""

    is_public = False
    is_full = False

    magic, key_bitlen = struct.unpack_from('<2L', blob, 0)

    # "RSA1"
    if magic == 0x31415352:
        is_public = True
    # "RSA3"
    elif magic == 0x33415352:
        is_full = True
    # "RSA2"
    elif magic != 0x32415352:
        return None

    e_size, n_size, p_size, q_size = struct.unpack_from('<4L', blob, 8)

    pos = 24
    e = int.from_bytes(blob[pos : pos + e_size], byteorder='big')
    pos += e_size
    n = int.from_bytes(blob[pos : pos + n_size], byteorder='big')

    if is_public:
        return RSA.construct((n, e))

    pos += n_size
    p = int.from_bytes(blob[pos : pos + p_size], byteorder='big')
    pos += p_size
    q = int.from_bytes(blob[pos : pos + q_size], byteorder='big')

    if not is_full:
        pos += 2 * (q_size + p_size)
        d = int.from_bytes(blob[pos : pos + n_size], byteorder='big')
    else:
        d = mod_inverse(e, (p - 1) * (q - 1))
        if d is None:
            return None

    return RSA.construct((n, e, d, p, q))


def get_aes_key_from_blob(blob: bytes) -> bytes:
    """Get AES key from BLOB"""

    # Parse key BLOB
    blob_size, blob_sign = struct.unpack_from('<2L', blob, 0)
    # "KSSM"
    if blob_sign != 0x4D53534B:
        return None

    key_size, = struct.unpack_from('<L', blob, AES_KEY_POS)
    return blob[AES_KEY_POS + 4 : AES_KEY_POS + 4 + key_size]


def compute_enc_marker_hash(enc_marker: bytes) -> int:
    """Compute encryption marker hash"""

    # Get xxHash32 seed
    seed = 0
    for i in range(len(enc_marker)):
        seed = (seed + enc_marker[i] + i) & 0xFFFF

    # Compute xxHash32
    return xxhash32.xxhash32(enc_marker, seed)


def check_enc_marker(metadata: bytes) -> bool:
    """Check encryption marker"""

    h, = struct.unpack_from('<L', metadata, ENC_MARKER_HASH_POS)
    return (h == compute_enc_marker_hash(metadata[:ENC_MARKER_SIZE]))


def check_encrypted_file(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        # Get file size
        f.seek(0, 2)
        file_size = f.tell()

        metadata_size = METADATA_SIZE

        for i in range(2):

            if file_size < metadata_size + 16:
                break

            # Read metadata
            f.seek(-metadata_size, 2)
            metadata = f.read(ENC_KEY_DATA_POS)

            # Check encryption marker
            if check_enc_marker(metadata):

                # Print metadata parameters
                enc_marker = metadata[:ENC_MARKER_SIZE]

                padding_size, block_step, big_file, aes_mode, \
                block_size, enc_marker_hash, num_blocks = \
                    struct.unpack_from('<4HLLQ', metadata, ENC_MARKER_SIZE)

                additional_data_size = metadata_size + padding_size
                if i > 0:
                    additional_data_size += AES_BLOCK_SIZE
                orig_file_size = file_size - additional_data_size

                print('encrypted:     %d' % (i + 1))
                print('original size: %d' % orig_file_size)
                print('metadata size: %d' % metadata_size)
                print('marker:        %s' %
                      binascii.hexlify(enc_marker).decode().upper())
                print('marker hash:   %08X' % enc_marker_hash)
                print('padding size:  %d' % padding_size)
                print('block step:    %d' % block_step)
                print('big file:      %d' % big_file)
                print('aes mode:      %d' % aes_mode)
                print('block size:    %08X' % block_size)
                print('blocks:        %d' % num_blocks)

                return True

            metadata_size += RSA_KEY_SIZE

    return False


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Get file size
        f.seek(0, 2)
        file_size = f.tell()

        encrypted = 0
        metadata_size = METADATA_SIZE

        for i in range(2):

            if file_size < metadata_size + 16:
                break

            # Read metadata
            f.seek(-metadata_size, 2)
            metadata = f.read(METADATA_SIZE)

            # Check encryption marker
            if check_enc_marker(metadata):
                encrypted = i + 1
                break

            metadata_size += RSA_KEY_SIZE

        if encrypted == 0:
            return False

        if encrypted == 2:
            # The file is re-encrypted
            # Read 2nd encrypted key data
            metadata += f.read(RSA_KEY_SIZE)

        # Decrypt AES key(s)
        keys = []

        cipher = PKCS1_v1_5.new(priv_key)

        for i in range(encrypted):

            # Get encrypted key data
            enc_key_data = metadata[ENC_KEY_DATA_POS + i * RSA_KEY_SIZE:
                                    ENC_KEY_DATA_POS +
                                    (i + 1) * RSA_KEY_SIZE]

            # Decrypt AES key data (RSA PKCS #1 v1.5)
            sentinel = os.urandom(SENTINEL_SIZE)
            key_data = cipher.decrypt(enc_key_data, sentinel)
            if key_data == sentinel:
                return False

            # Get AES key from BLOB
            key_blob = key_data[:AES_KEY_BLOB_SIZE]
            key = get_aes_key_from_blob(key_blob)
            if key is None:
                return False

            iv = key_data[AES_KEY_BLOB_SIZE:
                          AES_KEY_BLOB_SIZE + AES_IV_SIZE]

            keys.append((key, iv))

        key1 = keys[0][0]
        iv1 = keys[0][1]

        # Get metadata parameters
        padding_size, block_step, big_file, aes_mode, block_size = \
            struct.unpack_from('<4HL', metadata, ENC_MARKER_SIZE)
        num_blocks, = struct.unpack_from('<Q', metadata, NUM_BLOCKS_POS)

        additional_data_size = metadata_size + padding_size

        # Decrypt data
        if big_file != 0:

            # Decrypt big file
            additional_data_size += AES_BLOCK_SIZE

            if (encrypted == 2) and (1 <= aes_mode <= 2):

                # Decrypt stage #2
                key2 = keys[1][0]
                iv2 = keys[1][1]

                if aes_mode == 2:
                    # AES GCM
                    cipher = AES.new(key2, AES.MODE_GCM,
                                     iv2[:AES_GCM_NONCE_SIZE])
                else:
                    # AES CBC
                    cipher = AES.new(key2, AES.MODE_CBC, iv2)

                enc_size = (file_size -
                            (2 * block_size + metadata_size + padding_size))
                n_blocks, last_block_size = divmod(enc_size, block_size)
                if block_step > 1:
                    last_space_blocks = n_blocks % block_step
                else:
                    last_space_blocks = 0
                    block_step = 1

                pos = block_size

                while (n_blocks >= block_step) and (num_blocks > 2):

                    pos += (block_step - 1) * block_size

                    f.seek(pos)
                    enc_data = f.read(block_size)
                    if enc_data == b'':
                        break

                    data = cipher.decrypt(enc_data)

                    f.seek(pos)
                    f.write(data)

                    pos += block_size
                    num_blocks -= 1
                    n_blocks -= block_step

                if (last_block_size != 0) and (num_blocks > 2):

                    pos += last_space_blocks * block_size
                    f.seek(pos)
                    enc_data = f.read(last_block_size)
                    if enc_data != b'':

                        data = cipher.decrypt(enc_data)
                        f.seek(pos)
                        f.write(data)
                        num_blocks -= 1

            # Decrypt stage #1
            if num_blocks >= 2:

                cipher = AES.new(key1, AES.MODE_CBC, iv1)

                # Decrypt first block
                f.seek(0)
                enc_data = f.read(block_size)

                data = cipher.decrypt(enc_data)

                f.seek(0)
                f.write(data)

                # Decrypt last block
                pos = -(block_size + metadata_size + padding_size)

                # Restore last block first bytes
                f.seek(-(metadata_size + padding_size), 2)
                first_bytes = f.read(padding_size)

                f.seek(pos, 2)

                enc_data = f.read(block_size)
                enc_data = first_bytes + enc_data[padding_size:]
                data = cipher.decrypt(enc_data)

                f.seek(pos, 2)
                f.write(data)

        else:

            # Decrypt small file
            cipher = AES.new(key1, AES.MODE_CBC, iv1)

            enc_size = file_size - metadata_size

            pos = 0

            while (num_blocks != 0) and (enc_size != 0):

                size = min(enc_size, block_size)

                f.seek(pos)

                enc_data = f.read(size)
                if enc_data == b'':
                    break

                data = cipher.decrypt(enc_data)

                f.seek(pos)
                f.write(data)

                pos += size
                enc_size -= size
                num_blocks -= 1

        # Remove additional data
        f.seek(-additional_data_size, 2)
        f.truncate()

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Check if file is encrypted
if not check_encrypted_file(filename):
    print('Error: File not encrypted or damaged')
    sys.exit(1)

# Read RSA private key BLOB
with io.open('./rsa_privkey.bin', 'rb') as f:
    priv_key_blob = f.read()

# Get RSA private key from BLOB
priv_key = get_rsa_key_from_blob(priv_key_blob)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key):
    print('Error: Failed to decrypt file')
    sys.exit(1)
