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
import struct


CONFIG_RES_TYPE = 'SETTINGS'
CONFIG_RES_NAME = 101
CONFIG_RES_ID = 0

KEYS = [
    ( 24835043114418836, 45081017281842116),
    ( 49004104848533, 1981043465524)
]

CFG_CHECK_STR = b'ncryptedFileExtension'


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt (XOR)"""

    res_data = bytearray(data)
    for i in range(len(data)):
        res_data[i] ^= key[i % len(key)]
    return bytes(res_data)


def decrypt_cfg_data(data: bytes) -> bytes:
    """Decrypt configuration data"""

    for key_n1, key_n2 in KEYS:
        key_n = key_n1 * key_n2
        key_size = (key_n.bit_length() + 7) // 8
        key = key_n.to_bytes(key_size, byteorder='little')
        dec_data = xor_decrypt(data, key)
        if dec_data.find(CFG_CHECK_STR) > 0:
            return dec_data

    return None


def find_res_entry(res_name, file_data: bytes, res_pos: int,
                   offset: int) -> int:
    """Find resource entry"""

    is_name_id = isinstance(res_name, int)
    if not is_name_id and not isinstance(res_name, str):
        return -1

    pos = res_pos + (offset & 0x7FFFFFFF)

    num_named, num_ids = struct.unpack_from('<HH', file_data, pos + 12)

    pos += 16
    if is_name_id:
        pos += num_named * 8
        num_entries = num_ids
    else:
        num_entries = num_named
        res_name = res_name.encode('UTF-16-LE')

    for i in range(num_entries):

        nm, ofs = struct.unpack_from('<LL', file_data, pos + i * 8)
        if is_name_id:
            if res_name == nm:
                return ofs
        else:
            if nm & 0x80000000 != 0:
                name_pos = res_pos + (nm & 0x7FFFFFFF)
                name_len, = struct.unpack_from('<H', file_data, name_pos)
                name_pos += 2
                if res_name == file_data[name_pos : name_pos + 2 * name_len]:
                    return ofs

    return -1


def extract_pe_res(file_data: bytes, res_type, res_name, res_id) -> bytes:
    """Extract PE file resource"""

    mz_sign, = struct.unpack_from('<H', file_data, 0)
    if (mz_sign != 0x5A4D):
        return None

    nt_hdr_pos, = struct.unpack_from('<L', file_data, 0x3C)

    pe_sign, = struct.unpack_from('<L', file_data, nt_hdr_pos)
    if (pe_sign != 0x00004550):
        return None

    # Parse PE header
    img_hdr_pos = nt_hdr_pos + 4
    num_sections, = struct.unpack_from('<H', file_data, img_hdr_pos + 2)
    opt_hdr_pos = img_hdr_pos + 0x14
    opt_hdr_size, = struct.unpack_from('<H', file_data, img_hdr_pos + 0x10)
    nt_hdr_size = 4 + 0x14 + opt_hdr_size
    first_section_hdr_pos = nt_hdr_pos + nt_hdr_size
    opt_hdr_magic, = struct.unpack_from('<H', file_data, opt_hdr_pos)
    is_x64 = (opt_hdr_magic == 0x20B)

    # Directory
    dir_pos = opt_hdr_pos + 0x5C
    if is_x64:
        dir_pos += 0x10
    num_datadirs, = struct.unpack_from('<L', file_data, dir_pos)
    if num_datadirs > 16:
        num_datadirs = 16

    if num_datadirs < 3:
        return None

    # Resource directory entry
    res_rva, res_size = struct.unpack_from('<LL', file_data, dir_pos + 20)
    res_pos = None

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):

        s_vsize, s_rva, s_psize, s_pos = struct.unpack_from('<4L', file_data,
                                                            pos + 8)
        if (s_pos != 0) and (res_rva >= s_rva):
            ofs = res_rva - s_rva
            if ofs + res_size <= s_psize:
                res_pos = s_pos + ofs
                break

        pos += 0x28

    if res_pos is None:
        return None

    # Find resource type entry
    ofs = find_res_entry(res_type, file_data, res_pos, 0)
    if (ofs == -1) or (ofs & 0x80000000 == 0):
        return None

    # Find resource name entry
    ofs = find_res_entry(res_name, file_data, res_pos, ofs)
    if (ofs == -1) or (ofs & 0x80000000 == 0):
        return None

    # Find resource ID entry
    ofs = find_res_entry(res_id, file_data, res_pos, ofs)
    if (ofs == -1) or (ofs & 0x80000000 != 0):
        return None

    res_data_rva, res_data_size = struct.unpack_from('<LL', file_data,
                                                     res_pos + ofs)
    res_data_pos = res_pos + (res_data_rva - res_rva)
    return file_data[res_data_pos : res_data_pos + res_data_size]


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', sys.argv[0], 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    file_data = f.read()

# Extract encrypted configuration data from resources
enc_cfg_data = extract_pe_res(file_data, CONFIG_RES_TYPE, CONFIG_RES_NAME,
                              CONFIG_RES_ID)
if not enc_cfg_data:
    print('Error: Configuration data not found.')
    sys.exit(1)

# Decrypt configuration data
cfg_data = decrypt_cfg_data(enc_cfg_data)
if not cfg_data:
    print('Error: Invalid configuration data.')
    sys.exit(1)

new_filename = filename + '.cfg'
with io.open(new_filename, 'wb') as f:
    f.write(cfg_data)
