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
    '.Black',
    '.Cylance',      # Cylance (2023-03-24)
    '.uploaded',
    '.transferred',
    '.Antoni',
    '.Sezar'
]

# BTC (2023-06-12)
BTC_RANSOM_EXT = '.BTC'
BTC_RANSOM_EXT_PREFIX = '.EMAIL=['


# Encrypted session key data size (Cylance)
ENC_SESSSION_KEY_DATA_SIZE = 100


METADATA_SIZE = 64
METADATA_KEY_POS = 16
METADATA_KEY_CRC_POS = 56
METADATA_PUBKEY_CRC_POS = 60

# x25519
X25519_KEY_SIZE = 32

# ChaCha20
CHACHA_NONCE_SIZE = 8
CHACHA_ROUNDS = 8

# "hardcore blowjob"
CHACHA_CUSTOM_CONSTANTS = [0x64726168, 0x65726F63, 0x6F6C6220, 0x626F6A77]


ENC_BLOCK_SIZE = 0x100000


# CRC32
CRC32_POLY = 0x4C11DB7
crc32_table = None


def create_crc32_table() -> list:
    """Create CRC32 table"""

    table = list(range(256))

    for i in range(256):
        x = i << 24
        for j in range(8):
            if x & 0x80000000:
                x = (x << 1) ^ CRC32_POLY
            else:
                x <<= 1
        table[i] = x & 0xFFFFFFFF

    return table


def crc32(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """Get CRC32"""

    global crc32_table
    if crc32_table is None:
        crc32_table = create_crc32_table()

    for b in data:
        crc = ((crc & 0xFFFFFF) << 8) ^ crc32_table[((crc >> 24) & 0xFF) ^ b]
    return crc


def derive_encryption_key(priv_key_data: bytes, pub_key_data: bytes) -> bytes:
    """Derive encryption key"""

    # Derive x25519 shared secret
    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = priv_key.exchange(pub_key)

    # Derive encryption key
    return hashlib.sha256(shared_secret).digest()


def cylance_decrypt_session_priv_key(enc_key_data: bytes,
                                     master_priv_key_data: bytes) -> bytes:
    """Cylance: Decrypt session private key from encrypted key data"""

    # Derive XOR key
    pub_key_data = enc_key_data[2 * X25519_KEY_SIZE : 3 * X25519_KEY_SIZE]
    xor_key = derive_encryption_key(master_priv_key_data, pub_key_data)

    # Check XOR key CRC32
    xor_key_crc, = struct.unpack_from('<L', enc_key_data,
                                      3 * X25519_KEY_SIZE)
    if xor_key_crc != crc32(xor_key):
        return None

    # Get session public key
    s_pub_key_data = enc_key_data[X25519_KEY_SIZE : 2 * X25519_KEY_SIZE]

    # Decrypt session private key
    s_priv_key_data = bytearray(enc_key_data[:X25519_KEY_SIZE])
    for i in range(X25519_KEY_SIZE):
        s_priv_key_data[i] ^= xor_key[i]

    return bytes(s_priv_key_data)


def decrypt_file(filename: str,
                 priv_key_data: bytes,
                 enc_session_key_data_present: bool = False) -> bool:
    """
    Decrypt file.
    For Cylance (168): enc_session_key_data_present = True
    """

    with io.open(filename, 'rb+') as f:

        additional_data_size = METADATA_SIZE
        if enc_session_key_data_present:
            additional_data_size += ENC_SESSSION_KEY_DATA_SIZE + 4

        # Read metadata
        try:
            f.seek(-additional_data_size, 2)
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

        # Derive ChaCha20 encryption key
        key = derive_encryption_key(priv_key_data, pub_key_data)

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

        # Encryption mode (1 - full, 2 - fast, 3 - split)
        enc_mode, = struct.unpack_from('<L', info, 0)

        chunk_space = 0
        if enc_mode == 3:
            # split
            chunk_space, = struct.unpack_from('<Q', info, 8)

        # Remove metadata
        f.seek(-additional_data_size, 2)
        f.truncate()

        # Decrypt file data
        pos = 0

        while True:

            # Decrypt block
            f.seek(pos)
            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(pos)
            f.write(data)

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

fname, fext = os.path.splitext(filename)

if fext == BTC_RANSOM_EXT:

    pos = filename.find(BTC_RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename = filename[:pos]
    else:
        new_filename = filename + '.dec'

else:

    # Change ChaCha20 constants
    chacha.ChaCha.constants = CHACHA_CUSTOM_CONSTANTS

    if fext in RANSOM_EXTS:
        new_filename = fname
    else:
        new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)