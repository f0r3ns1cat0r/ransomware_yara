import sys
import io
import os
import alphv3_sphx_util
import alphv3_sphx_crypt


RND_STR_LEN = 32


def make_access_key(pub_key_data: bytes, access_token: str) -> str:
    """Make access-key from access-token"""

    # Get random string
    rnd_data = bytes(alphv3_sphx_util.get_rnd_str(RND_STR_LEN), 'ascii')

    # Make access-key data
    access_token_data = bytes(access_token, 'ascii')
    access_key_data = (alphv3_sphx_util.get_data_blob(rnd_data) +
                       alphv3_sphx_util.get_data_blob(access_token_data))

    # Encrypt access-key data
    enc_data = alphv3_sphx_crypt.rsa_encrypt(access_key_data, pub_key_data)

    # Encode encrypted data
    return alphv3_sphx_util.encode_data(alphv3_sphx_util.get_data_blob(enc_data))


def decrypt_access_key(priv_key_data: bytes, access_key: str) -> (str, str):
    """Decrypt access-key, extract access-token and random string"""

    # Decode encrypted access-key data
    data = alphv3_sphx_util.decode_data(access_key)
    enc_data = alphv3_sphx_util.extract_data_from_blob(data)
    if enc_data is None:
        return None

    # Decrypt access-key data
    access_key_data = alphv3_sphx_crypt.rsa_decrypt(enc_data, priv_key_data)
    if access_key_data is None:
        return None

    # Extract random string
    rnd_str = alphv3_sphx_util.extract_data_from_blob(access_key_data)
    if rnd_str is None:
        return None

    # Extract access-token
    access_token = alphv3_sphx_util.extract_data_from_blob(access_key_data,
                                                           8 + len(rnd_str))
    if access_token is None:
        return None

    return access_token.decode(), rnd_str.decode()


#
# Main
#
if (len(sys.argv) != 4) or ((sys.argv[1] != '-t') and (sys.argv[1] != '-k')):
    print('Usage:', os.path.basename(sys.argv[0]),
          '<-t access_token>|<-k access_key> key_file')
    sys.exit(0)

key_filename = sys.argv[3]
with io.open(key_filename, 'rb') as f:
    key_data = f.read()

if sys.argv[1] == '-t':

    #Make access-key from access-token
    access_token = sys.argv[2]
    access_key = make_access_key(key_data, access_token)
    print('access-key: \"%s\"' % access_key)

else:

    # Decrypt access-key
    access_key = sys.argv[2]
    res = decrypt_access_key(key_data, access_key)
    if res is None:
        print('Error: Failed to decrypt access-key.')
        sys.exit(1)

    print('access-token:  \"%s\"' % res[0])
    print('random string: \"%s\"' % res[1])