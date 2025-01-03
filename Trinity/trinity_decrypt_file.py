# MIT License
#
# Copyright (c) 2024 Andrey Zhdanov (rivitna)
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
import base64
import trinity_crypt


RANSOM_EXT = '.trinitylock'


# Metadata
ENC_KEY_DATA_SIZE = trinity_crypt.ENC_KEY_DATA_SIZE
NONCE_SIZE = trinity_crypt.XCHACHA20_NONCE_SIZE
METADATA_ENTRY_DATA_SIZE = 408
METADATA_SIZE = ENC_KEY_DATA_SIZE + NONCE_SIZE + METADATA_ENTRY_DATA_SIZE

METADATA_NUM_ENTRIES = 5
METADATA_DELIM = b';'


ENC_BLOCK_SIZE = 0x100000
ENC_BLOCK_STEP = 0x8000000


def decrypt_file(filename: str, priv_key_data: bytes,
                 is_master_key: bool = False) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < METADATA_SIZE:
            return False

        # Read metadata
        f.seek(-METADATA_SIZE, 2)
        metadata = f.read(METADATA_SIZE)

        entry_data_pos = ENC_KEY_DATA_SIZE + NONCE_SIZE

        enc_key_data = metadata[:ENC_KEY_DATA_SIZE]
        nonce = metadata[ENC_KEY_DATA_SIZE : entry_data_pos]

        # Get metadata entries
        entry_data_end_pos = metadata.find(0, entry_data_pos)
        if entry_data_end_pos >= 0:
            entry_data = metadata[entry_data_pos : entry_data_end_pos]
        else:
            entry_data = metadata[entry_data_pos:]

        entries = entry_data.split(METADATA_DELIM)
        if len(entries) < METADATA_NUM_ENTRIES:
            return False

        user = entries[0]
        victim_id = entries[1]
        s_pub_key_data = base64.b64decode(entries[3])
        orig_file_size = int(entries[4])

        print('user:', user.decode())
        print('victim_id:', victim_id.decode())
        print('file size:', orig_file_size)

        if orig_file_size + METADATA_SIZE > file_size:
            return False

        if is_master_key:

            # Decrypt session X25519 private key
            enc_s_key_data = base64.b64decode(entries[2])
            if len(enc_s_key_data) != trinity_crypt.ENC_SESSION_KEY_DATA_SIZE:
                return False

            s_priv_key_data = trinity_crypt.decrypt_session_key(enc_s_key_data,
                                                                priv_key_data)

        else:
            s_priv_key_data = priv_key_data

        # Check session X25519 public key
        pub_key_data = trinity_crypt.x25519_get_pubkey(s_priv_key_data)
        if pub_key_data != s_pub_key_data:
            return False

        # Decrypt XChaCha20 key
        key = trinity_crypt.curve25519xsalsa20poly1305_decrypt(enc_key_data,
                                                               s_priv_key_data)
        if not key:
            return False

        # Remove metadata
        f.truncate(orig_file_size)

        # Decrypt file data
        if orig_file_size < ENC_BLOCK_SIZE:
            block_size = orig_file_size
        else:
            block_size = ENC_BLOCK_SIZE

        pos = 0

        nonce = bytearray(nonce)

        while True:

            # Decrypt block
            f.seek(pos)
            enc_data = f.read(block_size)
            if enc_data == b'':
                break

            # Decrypt data (XChaCha20)
            data = trinity_crypt.chacha20_decrypt(enc_data, key, nonce)

            f.seek(pos)
            f.write(data)

            pos += ENC_BLOCK_STEP

            # Update XChaCha20 nonce
            n = 1
            for i in range(NONCE_SIZE):
                n += nonce[i]
                nonce[i] = n & 0xFF
                n >>= 8

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data, True):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
