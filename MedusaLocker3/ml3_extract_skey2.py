# MIT License
#
# Copyright (c) 2023-2025 Andrey Zhdanov (rivitna)
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
import base64
from Crypto.PublicKey import RSA
import ml3_crypt


# RSA
RSA_KEY_SIZE = 256

# Metadata
ENC_SESSION_RSA_KEY_SIZE = 5 * RSA_KEY_SIZE
METADATA_SIZE = ENC_SESSION_RSA_KEY_SIZE + RSA_KEY_SIZE + 8


def extract_session_key(filename: str, m_priv_key: RSA.RsaKey) -> bytes:
    """Extract session RSA key"""

    with io.open(filename, 'rb') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return None

        # Read encrypted session RSA private key
        enc_priv_key_blob = f.read(ENC_SESSION_RSA_KEY_SIZE)

    # Decrypt session RSA private key
    return ml3_crypt.decrypt_session_key(enc_priv_key_blob, m_priv_key)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read master RSA private key BLOB
with io.open('./privkey.txt', 'rb') as f:
    m_priv_key_blob = base64.b64decode(f.read())

# Get RSA private key from BLOB
m_priv_key = ml3_crypt.rsa_construct_blob(m_priv_key_blob)
if (m_priv_key is None) or not m_priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

# Extract session RSA key
s_priv_key_blob = extract_session_key(filename, m_priv_key)
if not s_priv_key_blob:
    print('Error: Failed to extract session RSA key')
    sys.exit(1)

skey_filename = filename + '.skey'
with io.open(skey_filename, 'wb') as f:
    f.write(base64.b64encode(s_priv_key_blob))
