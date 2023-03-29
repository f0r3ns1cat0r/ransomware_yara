import sys
import io
import os
import struct
import alphv3_dec
import alphv3_hash


CHAR_SET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

# ConfigKeyDump struct (key, noise, crc)
KEY_LEN = 16
MIN_CFG_KEY_DUMP_LEN = KEY_LEN + 8 + 2


def extract_cfg_key_from_string(s: str) -> bytes:
    """Extract cfg encryption key from string"""
    x = 0

    for c in s:
        n = CHAR_SET.find(c)
        if n < 0:
            raise ValueError('Invalid character')
        x = x * len(CHAR_SET) + n

    data_size = (x.bit_length() + 7) // 8
    data = x.to_bytes(data_size, byteorder='big')
    if len(data) < MIN_CFG_KEY_DUMP_LEN:
        return None

    # Skip noise
    noise_size, = struct.unpack_from('<Q', data, KEY_LEN)
    if noise_size > len(data) - MIN_CFG_KEY_DUMP_LEN:
        return None

    key = data[:KEY_LEN]

    # Compare CRC
    crc, = struct.unpack_from('<H', data, KEY_LEN + 8 + noise_size)
    crc2 = alphv3_hash.crc16(key)
    crc2 = alphv3_hash.crc16_finish(crc2)
    if crc != crc2:
        return None

    return key


def extract_cfg_key_from_args(args: list[str]) -> (bytes, str):
    """Extract cfg encryption key from command line arguments"""
    s = ''

    for arg in args:
        for c in arg:
            if (c == ' ') or (c == '-'):
                continue
            s += c
            # Extract cfg encryption key from string
            key = extract_cfg_key_from_string(s)
            if key is not None:
                return key, s

    return None


#
# Main
#
if len(sys.argv) < 2:
    print('Usage:', os.path.basename(sys.argv[0]), '<alphv command line>')
    sys.exit(0)

# Extract cfg encryption key from command line arguments
key_info = extract_cfg_key_from_args(sys.argv[1:])
if key_info is None:
    print('Error: Failed to extract encryption key.')
    sys.exit(1)

print('Key argument string: \"%s\"' % key_info[1])

with io.open('cfg_key.bin', 'wb') as f:
    f.write(key_info[0])