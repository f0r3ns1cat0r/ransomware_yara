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

import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
import salsa
import chacha


# x25519
X25519_KEY_SIZE = 32

# XChaCha20
XCHACHA20_KEY_SIZE = 32
XCHACHA20_NONCE_SIZE = 24

# XSalsa20-Poly1305
XSALSA20POLY1305_KEY_SIZE = 32
XSALSA20POLY1305_NONCE_SIZE = 24
XSALSA20POLY1305_MAC_SIZE = 16

# HSalsa
HSALSA_NONCE = 16 * b'\0'

# Curve25519XSalsa20Poly1305 box (Sodium)
CRYPTO_BOX_KEY_DATA_SIZE = X25519_KEY_SIZE + XSALSA20POLY1305_MAC_SIZE

# Encrypted session key data size
ENC_KEY_DATA_SIZE = XCHACHA20_KEY_SIZE + CRYPTO_BOX_KEY_DATA_SIZE
ENC_SESSION_KEY_DATA_SIZE = (X25519_KEY_SIZE + ENC_KEY_DATA_SIZE +
                             XCHACHA20_NONCE_SIZE)


def chacha20_decrypt(enc_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt XChaCha20"""

    cipher = chacha.ChaCha(key, nonce)
    return cipher.decrypt(enc_data)



def x25519_get_pubkey(priv_key_data: bytes) -> bytes:
    """Get X25519 public key"""

    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    pub_key = priv_key.public_key()
    return pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def curve25519xsalsa20poly1305_decrypt(box_data: bytes,
                                       priv_key_data: bytes) -> bytes:
    """Decrypt Curve25519XSalsa20Poly1305 box (Sodium)"""

    if len(box_data) < CRYPTO_BOX_KEY_DATA_SIZE:
        return None

    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    rem_pub_key = priv_key.public_key()
    rem_pub_key_data = rem_pub_key.public_bytes(Encoding.Raw,
                                                PublicFormat.Raw)

    pub_key_data = box_data[:X25519_KEY_SIZE]

    # Get XSalsa20-Poly1305 nonce
    h = hashlib.blake2b(digest_size=XSALSA20POLY1305_NONCE_SIZE)
    h.update(pub_key_data)
    h.update(rem_pub_key_data)
    nonce = h.digest()

    # Get XSalsa20-Poly1305 key
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = priv_key.exchange(pub_key)
    key = salsa.hsalsa(shared_secret, HSALSA_NONCE)

    # XSalsa20-Poly1305 decrypt
    mac_tag = box_data[X25519_KEY_SIZE :
                       X25519_KEY_SIZE + XSALSA20POLY1305_MAC_SIZE]
    enc_data = box_data[X25519_KEY_SIZE + XSALSA20POLY1305_MAC_SIZE:]
    cipher = salsa.Salsa(salsa.Salsa.init_state(key, nonce))
    # !!! Crutch: XSalsa20 -> XSalsa20-Poly1305 :-)
    cipher.decrypt(32 * b'\0')
    data = cipher.decrypt(enc_data)

    return data


def decrypt_session_key(enc_session_key_data: bytes,
                        master_priv_key_data: bytes) -> bytes:
    """Decrypt session private key"""

    enc_priv_key_data = enc_session_key_data[:X25519_KEY_SIZE]
    enc_key_data = enc_session_key_data[X25519_KEY_SIZE:
                                        X25519_KEY_SIZE + ENC_KEY_DATA_SIZE]
    nonce = enc_session_key_data[X25519_KEY_SIZE + ENC_KEY_DATA_SIZE:
                                 X25519_KEY_SIZE + ENC_KEY_DATA_SIZE +
                                 XCHACHA20_NONCE_SIZE]

    # Decrypt XChaCha20 key
    key = curve25519xsalsa20poly1305_decrypt(enc_key_data,
                                             master_priv_key_data)
    if not key:
        return None

    # Decrypt XChaCha20
    cipher = chacha.ChaCha(key, nonce)
    return cipher.decrypt(enc_priv_key_data)


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io
    import base64

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    with io.open('./privkey.txt', 'rb') as f:
        master_priv_key_data = base64.b64decode(f.read())

    with io.open(filename, 'rb') as f:
        enc_session_key_data = base64.b64decode(f.read())

    # Decrypt session private key
    s_priv_key_data = decrypt_session_key(enc_session_key_data,
                                          master_priv_key_data)
    if not s_priv_key_data:
        print('Error: Failed to decrypt session private key')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(s_priv_key_data)
