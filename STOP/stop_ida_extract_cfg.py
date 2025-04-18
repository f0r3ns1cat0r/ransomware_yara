# MIT License
#
# Copyright (c) 2023-2024 Andrey Zhdanov (rivitna)
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

import os
import io
import errno
import idautils
import idaapi


DECRYPT_FUNC_EA = 0x40EF50
DECRYPT_FUNC_NAME = 'decrypt_data_chunks'
DECRYPT_FUNC_TYPE = 'void __usercall decrypt_data_chunks(' \
                       'void *enc_chunk_list@<ecx>, ' \
                       'void *buf@<edx>, ' \
                       'int num_chunks)'


XOR_MASK = 0x80
CHUNK_SIZE = 0x97

CFG_DIR_PATH = './cfg/'


def get_push_arg_val(ea):
    """Get function argument (push)"""

    inst = idautils.DecodeInstruction(ea)
    if (inst.itype != idaapi.NN_push) or (inst.ops[0].type != o_imm):
        return None
    return inst.ops[0].value


def get_mov_arg_val(ea):
    """Get function argument (mov)"""

    inst = idautils.DecodeInstruction(ea)
    if (inst.itype != idaapi.NN_mov) or (inst.ops[1].type != o_imm):
        return None

    return inst.ops[1].value


def get_enc_data(call_ea):
    """Get encrypted data"""

    arg_addrs = idaapi.get_arg_addrs(call_ea)
    if arg_addrs is None:
        return None

    chunk_list_ea = get_mov_arg_val(arg_addrs[0])
    if chunk_list_ea is None:
        return None

    num_chunks = get_push_arg_val(arg_addrs[2])
    if num_chunks is None:
        return None

    return chunk_list_ea, num_chunks


def mkdirs(dir):
    """Create directory hierarchy"""

    try:
        os.makedirs(dir)

    except OSError as exception:
        if (exception.errno != errno.EEXIST):
            raise


def save_data_to_file(file_name, data):
    """Save binary data to file"""
    with io.open(file_name, 'wb') as f:
        f.write(data)


#
# Main
#

# Rename decryption function
set_name(DECRYPT_FUNC_EA, DECRYPT_FUNC_NAME)

# Set decryption function type
pt = parse_decl(DECRYPT_FUNC_TYPE, PT_SIL)
if pt is not None:
    apply_type(DECRYPT_FUNC_EA, pt, TINFO_DEFINITE)
    auto_wait()

# Create destination directory
dest_dir = CFG_DIR_PATH
mkdirs(dest_dir)

for xref in CodeRefsTo(DECRYPT_FUNC_EA, 1):

    enc_data_info = get_enc_data(xref)
    if enc_data_info is None:
        print('%08X: Failed to get encryption data.' % xref)
        continue

    print('Encrypted data: %08X (%d chunks)' % enc_data_info)

    # Decrypt and merge chunks
    data = b''

    for i in range(enc_data_info[1]):

        chunk_ea = ida_bytes.get_dword(enc_data_info[0] + i * 4)
        chunk_data = bytearray(ida_bytes.get_bytes(chunk_ea, CHUNK_SIZE))

        # Decrypt chunk data
        for j in range(CHUNK_SIZE):
            chunk_data[j] ^= XOR_MASK

        chunk_data_len = chunk_data.find(0)
        if chunk_data_len <= 0:
            break

        data += bytes(chunk_data[:chunk_data_len])

    if chunk_data_len < 0:
        print('%08X: Invalid configuration data.' % enc_data_info[0])
        continue

    i = data.find(0)
    if i >= 0:
        data = data[:i]

    save_data_to_file(dest_dir + ('cfg_%08X.bin' % enc_data_info[0]), data)

    # Add comments
    s = data.decode()
    s = s.encode('unicode_escape').decode().replace('\"', '\\"')
    set_cmt(xref, '\"' + s + '\"', 1)
    set_cmt(enc_data_info[0], '\"' + s + '\"', 1)
