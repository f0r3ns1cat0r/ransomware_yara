import sys
import io
import os
import shutil
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from Crypto.Cipher import AES
from Crypto.Util import Counter


RANSOM_EXT = '.INC'


ENC_MARKER = b'INC'

# x25519
X25519_KEY_SIZE = 32

# AES
AES_KEY_SIZE = 16
AES_IV_SIZE = 16

METADATA_SIZE = X25519_KEY_SIZE + len(ENC_MARKER)


ENC_BLOCK_SIZE = 1000000
ENC_BLOCK_STEP = 3 * ENC_BLOCK_SIZE


def derive_encryption_key_data(priv_key_data: bytes,
                               pub_key_data: bytes) -> bytes:
    """Derive encryption key data"""

    # Derive x25519 shared secret
    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = priv_key.exchange(pub_key)

    # Derive encryption key data
    return hashlib.sha512(shared_secret).digest()


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        if metadata[-len(ENC_MARKER):] != ENC_MARKER:
            return False

        pub_key_data = metadata[:X25519_KEY_SIZE]

        # Derive encryption key data
        key_data = derive_encryption_key_data(priv_key_data, pub_key_data)

        # AES-128 CTR
        key = key_data[:AES_KEY_SIZE]
        iv = key_data[AES_KEY_SIZE : AES_KEY_SIZE + AES_IV_SIZE]
        init_val = int.from_bytes(iv, byteorder='big')
        counter = Counter.new(128, initial_value=init_val,
                              little_endian=False)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

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

            data = cipher.decrypt(enc_data)

            f.seek(pos)
            f.write(data)

            pos += ENC_BLOCK_STEP

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('privkey.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)