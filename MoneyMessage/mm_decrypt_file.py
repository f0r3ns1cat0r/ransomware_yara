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
import shutil
import struct
import zlib
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import chacha


# ECDH SECT571K1 (NIST K-571)
ECDH_KEY_SIZE = 72
EDCH_PUB_KEY_SIZE = 2 * ECDH_KEY_SIZE
EDCH_SHARED_KEY_SIZE = 2 * ECDH_KEY_SIZE

# ChaCha20
NONCE_SIZE = 12

METADATA_SIZE = 0xAC
METADATA_NONCE_POS = 0x94

BLOCK_SIZE = 0x2000


def ecdh_derive_shared_key(priv_key_data: bytes,
                           peer_pub_key_data: bytes) -> bytes:
    """Derive ECDH shared key"""

    # Get private key value
    priv_val = int.from_bytes(priv_key_data, byteorder='little')

    # Get peer public key coordinates
    pub_x = int.from_bytes(peer_pub_key_data[:ECDH_KEY_SIZE],
                           byteorder='little')
    pub_y = int.from_bytes(peer_pub_key_data[ECDH_KEY_SIZE:],
                           byteorder='little')

    curve = ec.SECT571K1()

    backend = default_backend()
    libcrypto = backend._lib

    nid = backend._elliptic_curve_to_nid(curve)
    group = libcrypto.EC_GROUP_new_by_curve_name(nid)

    with backend._tmp_bn_ctx() as bn_ctx:

        # Set public point
        bn_pub_x = backend._ffi.gc(backend._int_to_bn(pub_x),
                                   libcrypto.BN_free)
        bn_pub_y = backend._ffi.gc(backend._int_to_bn(pub_y),
                                   libcrypto.BN_free)

        point = libcrypto.EC_POINT_new(group)
        point = backend._ffi.gc(point, libcrypto.EC_POINT_free)
        res = libcrypto.EC_POINT_set_affine_coordinates(group, point,
                                                        bn_pub_x, bn_pub_y,
                                                        bn_ctx)
        if res != 1:
            return None

        bn_priv_val = backend._ffi.gc(backend._int_to_bn(priv_val),
                                      libcrypto.BN_clear_free)

        # Derive shared secret point
        res = libcrypto.EC_POINT_mul(group, point, backend._ffi.NULL, point,
                                     bn_priv_val, bn_ctx)
        if res != 1:
            return None

        # Get shared secret point coordinates
        bn_shared_x = libcrypto.BN_CTX_get(bn_ctx)
        bn_shared_y = libcrypto.BN_CTX_get(bn_ctx)
        res = libcrypto.EC_POINT_get_affine_coordinates(group, point,
                                                        bn_shared_x,
                                                        bn_shared_y,
                                                        bn_ctx)
        if res != 1:
            return None

        shared_x = backend._bn_to_int(bn_shared_x)
        shared_y = backend._bn_to_int(bn_shared_y)

    return (shared_x.to_bytes(ECDH_KEY_SIZE, byteorder='little') +
            shared_y.to_bytes(ECDH_KEY_SIZE, byteorder='little'))


def decrypt_file(filename, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Check CRC
        crc, = struct.unpack_from('<L', metadata, METADATA_SIZE - 4)
        if crc != zlib.crc32(metadata[:METADATA_SIZE - 4]):
            return False

        # Get ECDH public key
        pub_key_len, = struct.unpack_from('<L', metadata, 0)
        if pub_key_len > EDCH_PUB_KEY_SIZE:
            return False

        pub_key_data = metadata[4 : 4 + pub_key_len]

        # Derive ECDH shared key
        shared_key_data = ecdh_derive_shared_key(priv_key_data, pub_key_data)
        if shared_key_data is None:
            return False

        # Get ChaCha20 key
        h = hashlib.sha3_256()
        h.update(shared_key_data)
        key = h.digest()

        # Get ChaCha20 nonce, counter
        counter, = struct.unpack_from('<L', metadata, METADATA_NONCE_POS)
        nonce = metadata[METADATA_NONCE_POS + 4 :
                         METADATA_NONCE_POS + 4 + NONCE_SIZE]

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        pos = 0

        while True:

            f.seek(pos)
            enc_data = f.read(BLOCK_SIZE)
            if enc_data == b'':
                break

            cipher = chacha.ChaCha(key, nonce, counter)
            dec_data = cipher.decrypt(enc_data)
            f.seek(pos)
            f.write(dec_data)

            pos += BLOCK_SIZE

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./priv_key.bin', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename + '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)
