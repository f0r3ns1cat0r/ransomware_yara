import sys
import io
import os.path


MARKER1 = b'wxyz0123456789+/'
MARKER2 = b'LoopError'
MAX_MARKER_SPACE = 32
NUM_PUBKEYS = 2
PUBKEY_SIZE = 32


#
# Main
#

if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    file_data = f.read()

pos = file_data.find(MARKER1)
if (pos < 0):
    raise Exception('Marker1 not found')

pos += len(MARKER1)

pos = file_data.find(MARKER2, pos, pos + MAX_MARKER_SPACE + len(MARKER2))
if (pos < 0):
    raise Exception('Marker2 not found')

pos += len(MARKER2)

pubkeys = file_data[pos : pos + NUM_PUBKEYS * PUBKEY_SIZE]

key_filepath = os.path.join(os.path.dirname(file_name), 'pubkeys.bin')
with io.open(key_filepath, 'wb') as f:
    f.write(pubkeys)

print('Done!')