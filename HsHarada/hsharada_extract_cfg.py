# MIT License
#
# Copyright (c) 2023 Andrey Zhdanov (rivitna)
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
import struct
import zlib


MARKER = b'\xFE\x09\x00\x00\x8D'


def decompress_data(data):
    """Decompress data"""
    decompress = zlib.decompressobj(-zlib.MAX_WBITS)
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated


#
# Main
#
if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    file_data = f.read()

pos = 0

# Find configuration data
while True:

    pos = file_data.find(MARKER, pos)
    if pos < 0:
        break
    pos += len(MARKER)

    # stsfld
    if file_data[pos + 4] != 0x80:
        continue
    cfg_data_token, = struct.unpack_from('<L', file_data, pos + 5)

    # ldsfld
    if file_data[pos + 9] != 0x7E:
        continue
    token, = struct.unpack_from('<L', file_data, pos + 10)
    if token == cfg_data_token:
        pos += 9
        break

if pos < 0:
    print('Error: Configuration data not found.')
    sys.exit(1)

print('cfg data position: %08X' % pos)
print('cfg data token: 0x%08X' % cfg_data_token)

cfg_data_dict = {}

# Parse IL code
while pos + 16 <= len(file_data):

    # ldsfld
    if file_data[pos] != 0x7E:
        break
    pos += 1
    token, = struct.unpack_from('<L', file_data, pos)
    if token != cfg_data_token:
        break
    pos += 4

    # ldc.i4
    if file_data[pos] != 0x20:
        break
    pos += 1
    idx, = struct.unpack_from('<L', file_data, pos)
    if cfg_data_dict.get(idx) is not None:
        break
    pos += 4

    # ldc.i4, stelem.i1
    if (file_data[pos] != 0x20) or (file_data[pos + 5] != 0x9C):
        break
    pos += 1
    val, = struct.unpack_from('<L', file_data, pos)
    if val > 255:
        break
    pos += 5

    cfg_data_dict[idx] = val

    # skip nop
    if file_data[pos] == 0:
        pos += 1

pack_cfg_data_size = max(cfg_data_dict.keys()) + 1
print('compressed cfg data size: %d' % pack_cfg_data_size)

pack_cfg_data = b'' 
for i in range(pack_cfg_data_size):
    val = cfg_data_dict.get(i)
    if val is None:
        break
    pack_cfg_data += bytes([val])

cfg_data = decompress_data(pack_cfg_data)
print('cfg data size: %d' % len(cfg_data))

cfg_filename = filename + '.cfg'
with io.open(cfg_filename, 'wb') as f:
    f.write(cfg_data)