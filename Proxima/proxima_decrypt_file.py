import sys
import io
import os
import shutil
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
import chacha


RANSOM_EXTS = [
    '.BLackShadow',
    '.BLackSh',
    '.BlackStore',
    '.uploaded'
]


METADATA_SIZE = 64
METADATA_KEY_POS = 16
X25519_KEY_SIZE = 32
METADATA_KEY_CRC_POS = 56
METADATA_PUBKEY_CRC_POS = 60

# ChaCha20
CHACHA_NONCE_SIZE = 8
CHACHA_ROUNDS = 8


ENC_BLOCK_SIZE = 0x100000


# CRC32
CRC32_POLY = 0x4C11DB7
crc32_table = None


def create_crc32_table(poly: int) -> list:
    """Get CRC32 table"""

    table = list(range(256))

    for i in range(256):
        x = (i << 24) & 0xFFFFFFFF
        for j in range(8):
            if x & 0x80000000:
                x = (x << 1) ^ poly
            else:
                x <<= 1
        table[i] = x & 0xFFFFFFFF

    return table


def crc32(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """Get CRC32"""

    global crc32_table
    if crc32_table is None:
        crc32_table = create_crc32_table(CRC32_POLY)

    for b in data:
        crc = crc32_table[((crc >> 24) & 0xFF) ^ b] ^ ((crc & 0xFFFFFF) << 8)
    return crc


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        pub_key_data = metadata[METADATA_KEY_POS :
                                METADATA_KEY_POS + X25519_KEY_SIZE]

        # Check public key CRC32
        pub_key_crc, = struct.unpack_from('<L', metadata,
                                          METADATA_PUBKEY_CRC_POS)
        if pub_key_crc != crc32(pub_key_data):
            return False

        # Derive Curve25519-donna shared key
        priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
        pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
        shared_secret = priv_key.exchange(pub_key)

        # Get ChaCha20 encryption key
        key = hashlib.sha256(shared_secret).digest()

        nonce = metadata[METADATA_KEY_POS + X25519_KEY_SIZE :
                         METADATA_KEY_POS + X25519_KEY_SIZE +
                         CHACHA_NONCE_SIZE]

        # Check encryption key CRC32
        key_crc, = struct.unpack_from('<L', metadata, METADATA_KEY_CRC_POS)
        if key_crc != crc32(key):
            return False

        cipher = chacha.ChaCha(key, nonce, 0, CHACHA_ROUNDS)

        # Decrypt encryption info
        enc_info = metadata[:METADATA_KEY_POS]
        info = cipher.decrypt(enc_info)

        # Encryption mode (1 - full, 2 - fast, 2 - split)
        enc_mode, = struct.unpack_from('<L', info, 0)

        chunk_space = 0
        if enc_mode == 3:
            # split
            chunk_space, = struct.unpack_from('<Q', info, 8)

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        # Decrypt file data
        pos = 0

        while True:

            # Decrypt block
            f.seek(pos)
            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            dec_data = cipher.decrypt(enc_data)

            f.seek(pos)
            f.write(dec_data)

            if enc_mode == 2:
                # fast (single block)
                break

            pos += ENC_BLOCK_SIZE + chunk_space

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('privkey.bin', 'rb') as f:
    priv_key_data = f.read(X25519_KEY_SIZE)

# "hardcore blowjob"
chacha.ChaCha.constants = [0x64726168, 0x65726F63, 0x6F6C6220, 0x626F6A77]

# Copy file
new_filename = filename

for ransom_ext in RANSOM_EXTS:
    if new_filename.endswith(ransom_ext):
        new_filename = new_filename[:-len(ransom_ext)]
        break
else:
    new_filename += '.dec'

shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)