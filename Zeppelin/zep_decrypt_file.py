import sys
import io
import struct
import shutil
import zep_dec
import zep_crypt


RANSOM_EXT = 'xxxxxx'


MARKER0 = b'\xDA\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xBF\x0D\x0A\xB3'
MARKER1 = b'ZEPPELIN'
MARKER2 = b'\xB3\x0D\x0A\xC0\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xD9\x0D\x0A'


def is_file_encrypted(filename):
    """Check if file is encrypted"""

    marker = MARKER0 + MARKER1 + MARKER2

    with io.open(filename, 'rb') as f:
        data = f.read(len(marker))

    return (data == marker)



def decrypt_file(filename, rsa155_n, rsa155_d):
    """Decrypt file"""

    marker = MARKER0 + MARKER1 + MARKER2

    with io.open(filename, 'rb+') as f:

        f.seek(len(marker))
        data = f.read(16)
        enc_size, orig_size = struct.unpack_from('<QQ', data, 0)

        f.seek(-4, 2)
        data = f.read(4)
        metadata_size = int.from_bytes(data, byteorder='little')

        # Read metadata
        try:
            f.seek(-metadata_size, 2)
        except OSError:
            return False
        metadata = f.read(metadata_size)

        pos = 0

        # Block offset list
        size, = struct.unpack_from('<L', metadata, pos)
        pos += 4
        off_list_data = zep_dec.decrypt_data(metadata[pos : pos + size])
        pos += size

        num_blocks = len(off_list_data) // 8
        block_offsets = list(struct.unpack('<' + str(num_blocks) + 'Q',
                                           off_list_data))

        # Encrypted AES key and IV
        size, = struct.unpack_from('<L', metadata, pos)
        pos += 4
        enc_key_data = zep_dec.decrypt_data(metadata[pos : pos + size])
        key_data = zep_crypt.rsa_decrypt(rsa155_n, rsa155_d,
                                         int(enc_key_data))
        pos += size

        # Encrypted RSA-155 private key
        size, = struct.unpack_from('<L', metadata, pos)
        pos += 4 + size

        # Block size, original file size
        block_size, file_size = struct.unpack_from('<LQ', metadata, pos)

        # Encrypted data
        enc_data = b''

        for off in block_offsets:
            size = block_size
            if off == 0:
                off = len(marker)
                size -= len(marker)
            f.seek(off)
            enc_data += f.read(size)

        f.seek(file_size)
        enc_data += f.read(enc_size + len(marker) + 16 -
                           num_blocks * block_size)

        dec_data = zep_crypt.aes_decrypt(enc_data,
                                         key_data[:zep_crypt.AES_KEY_LEN],
                                         key_data[zep_crypt.AES_KEY_LEN:])

        for i, off in enumerate(block_offsets):
            f.seek(off)
            f.write(dec_data[i * block_size : (i + 1) * block_size])

        # Remove metadata
        f.seek(file_size)
        f.truncate()

    return True


def get_victim_id(rsa155_n_s):
    """Get Victim ID"""
    v_id = rsa155_n_s[:3] + '-' + rsa155_n_s[4:7] + '-' + rsa155_n_s[8:11]
    return v_id.upper()


#
# Main
#
if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

filename = sys.argv[1]

# Check if file is encrypted
if not is_file_encrypted(filename):
    print('Error: file not encrypted or damaged')
    sys.exit(1)

# Decrypt file
with io.open('rsa155_n.txt', 'rt') as f:
    s = f.read()
    victim_id = get_victim_id(s)
    rsa155_n = int(s, 16)

with io.open('rsa155_d.txt', 'rt') as f:
    rsa155_d = int(f.read(), 16)

ransom_ext = '.' + RANSOM_EXT + '.' + victim_id

new_filename = filename
if new_filename.endswith(ransom_ext):
    new_filename = new_filename[:-len(ransom_ext)]
else:
    new_filename += '.dec'
shutil.copy2(filename, new_filename)

if not decrypt_file(new_filename, rsa155_n, rsa155_d):
    print('Error: file damaged')
    sys.exit(1)