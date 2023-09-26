import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA OAEP decrypt data"""

    key = RSA.import_key(priv_key_data)
    decryptor = PKCS1_OAEP.new(key, hashAlgo=SHA1)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def b64decode_and_rsa_decrypt(enc_data: bytes,
                              priv_key_data: bytes) -> bytes:
    """Base64 decode and RSA OAEP decrypt data"""

    return rsa_decrypt(base64.b64decode(enc_data), priv_key_data)


if __name__ == '__main__':
    import sys
    import io
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    with io.open('rsa_privkey.txt', 'rb') as f:
        priv_key_data = base64.b64decode(f.read())

    with io.open(filename, 'rb') as f:
        enc_data = f.read()

    # Base64 decode and RSA decrypt data
    data = b64decode_and_rsa_decrypt(enc_data, priv_key_data)
    if data is None:
        print('Error: Failed to decrypt data')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(data)