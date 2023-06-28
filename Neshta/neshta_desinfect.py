import sys
import io
import os
import struct
import shutil


VIRUS_SIZE = 0xA200
SEED_POS = 1234
ENC_SIZE = 1000


def decrypt_data(data, seed):
    """Decrypt data"""

    res_data = bytearray(data)

    for i in range(len(res_data)):
        seed = (seed * 0x8088405 + 1) & 0xFFFFFFFF
        res_data[i] ^= (seed * 0xFF) >> 32

    return bytes(res_data)


def desinfect_file(filename):
    """Desinfect file"""

    with io.open(filename, 'rb+') as f:

        # Read begin data
        try:
            f.seek(-VIRUS_SIZE, 2)
        except OSError:
            return False

        begin_part = f.read(VIRUS_SIZE)

        # Decrypt begin data
        seed, = struct.unpack_from('<L', begin_part, SEED_POS)
        dec_data = decrypt_data(begin_part[:ENC_SIZE], seed)

        # Restore begin data
        f.seek(0)
        f.write(dec_data + begin_part[ENC_SIZE:])

        # Restore file size
        f.seek(-VIRUS_SIZE, 2)
        f.truncate()

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Copy file
new_filename = filename + '.dec'
shutil.copy(filename, new_filename)

# Desinfect file
if not desinfect_file(new_filename):
    print('Error: Failed to desinfect file')
    sys.exit(1)