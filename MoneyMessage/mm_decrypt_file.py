import sys
import io
import shutil
import struct
import zlib
import hashlib
import chacha


MAX_PUB_KEY_LEN = 0x90
KEY_LEN = 32
IV_LEN = 12

METADATA_SIZE = 0xAC
METADATA_IV_POS = 0x94

BLOCK_SIZE = 0x2000


def decrypt_file(filename, shared_key):
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
        if pub_key_len > MAX_PUB_KEY_LEN:
            return False

        pub_key = metadata[4 : 4 + pub_key_len]

        # TODO: ECDH 571K1 (?) implementation

        # Get ChaCha20 key
        h = hashlib.sha3_256()
        h.update(shared_key)
        key = h.digest()

        # Get ChaCha20 iv, counter
        counter, = struct.unpack_from('<L', metadata, METADATA_IV_POS)
        iv = metadata[METADATA_IV_POS + 4 : METADATA_IV_POS + 4 + IV_LEN]

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        pos = 0

        while True:

            f.seek(pos)
            enc_data = f.read(BLOCK_SIZE)
            if enc_data == b'':
                break

            cipher = chacha.ChaCha(key, iv, counter)
            dec_data = cipher.decrypt(enc_data)
            f.seek(pos)
            f.write(dec_data)

            pos += BLOCK_SIZE

    return True


if len(sys.argv) != 2:
    print("Usage: "+ sys.argv[0] + " filename")
    exit(0)

filename = sys.argv[1]

with io.open('shared_key.bin', "rb") as f:
    shared_key = f.read()

# Copy file
new_filename = filename + '.dec'
shutil.copy(filename, new_filename)

if not decrypt_file(new_filename, shared_key):
    print('Error: Failed to decrypt file')
    sys.exit(1)