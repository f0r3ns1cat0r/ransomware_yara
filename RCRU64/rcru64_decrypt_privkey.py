import sys
import io
import os
import base64
import rcru64_crypt


ENC_PART_MARKER1 = b'L8a'
ENC_PART_MARKER2 = b'J7x23'


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('rsa_privkey2.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

with io.open(filename, 'rb') as f:
    enc_data = f.read()

pos = enc_data.find(ENC_PART_MARKER1)
if pos < 0:
    print('Error: Invalid encrypted private key data')
    sys.exit(1)

pos += len(ENC_PART_MARKER1)
enc_data = enc_data[pos:]
key_parts = enc_data.split(ENC_PART_MARKER2, 2)

# Base64 decode and RSA decrypt private key part #0
key_part0 = rcru64_crypt.b64decode_and_rsa_decrypt(key_parts[0],
                                                   priv_key_data)
if key_part0 is None:
    print('Error: Failed to decrypt private key part #0')
    sys.exit(1)

data = key_part0 + key_parts[1]

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(data)