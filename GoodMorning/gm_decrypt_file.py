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
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


PASSWORD = '7b87952a42d79d02189ba9469ef5e678d1c221b4bd998b164e82d6531a907f526dff7d89d6cabf74'

VICTIM_ID = '00000000'
EMAIL1 = 'mail@mail.com'

#RANSOM_EXT = 'Id(' + VICTIM_ID + ') Send Email(' + EMAIL1 + ').GoodMorning'
#RANSOM_EXT = 'Id = ' + VICTIM_ID + ' Email = ' + EMAIL1 + ' .LOCKED'
#RANSOM_EXT = '+Id(' + VICTIM_ID + ') mail(' + EMAIL1 + ').REAL'
RANSOM_EXT = '+Id(' + VICTIM_ID + ') mail(' + EMAIL1 + ').KKK'


FILE_SIZE_STR_SIZE = 16
AES_IV_SIZE = 16
METADATA_SIZE = FILE_SIZE_STR_SIZE + AES_IV_SIZE


CHUNK_SIZE = 0x10000


def get_key(password: str) -> bytes:
    """Get encryption key"""
    h = SHA256.new(password.encode('utf-8'))
    return h.digest()


def decrypt_file(filename, new_filename: str, key: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb') as infile:
        with io.open(new_filename, 'wb') as outfile:

            # Read metadata
            metadata = infile.read(METADATA_SIZE)
            file_size = int(metadata[:FILE_SIZE_STR_SIZE])
            iv = metadata[FILE_SIZE_STR_SIZE:]

            cipher = AES.new(key, AES.MODE_CBC, iv)

            while True:

                chunk_data = infile.read(CHUNK_SIZE)
                if chunk_data == b'':
                    break

                chunk_data = cipher.decrypt(chunk_data)
                outfile.write(chunk_data)

            outfile.truncate(file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'

# Decrypt file
if not decrypt_file(filename, new_filename, get_key(PASSWORD)):
    print('Error: Failed to decrypt file')
    sys.exit(1)
