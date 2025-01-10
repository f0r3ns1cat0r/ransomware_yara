# MIT License
#
# Copyright (c) 2025 Andrey Zhdanov (rivitna)
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
import os
import errno
import struct
from Crypto.Cipher import AES

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    HAVE_UNICORN = False
else:
    HAVE_UNICORN = True


# Configuration data file position
# If None try detect automatically position
CFG_POS = None  # 0x9400
# Configuration data section name
CFG_SECTION_NAME = b'.ndata'

# Import configuration data key function position
IMPORTCFGKEY_FUNC_POS = 0x1C10
MAX_IMPORTCFGKEY_CODE_SIZE = 200


CFG_KEY_LEN = 32
CFG_IV = 16 * b'\0'

CFG_ENTRY_SIZE = 8


# Emulation
BASE_ADDR = 0x10000
# Stack
STACK_SIZE = 0x10000
STACK_INIT_POS = (STACK_SIZE // 2) & ~0xFF


def get_cfg_info(file_data):
    """Get configuration data information"""

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

    cfg_pos = None

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):

        s_name = file_data[pos : pos + 8]
        i = s_name.find(0)
        if (i >= 0):
            s_name = s_name[:i]

        if s_name == CFG_SECTION_NAME:
            s_vsize, s_rva, s_psize, s_pos = struct.unpack_from('<4L',
                                                                file_data,
                                                                pos + 8)
            if s_pos != 0:
                cfg_size = min(s_vsize, s_psize)
                if cfg_size > 8:
                    cfg_pos = s_pos
                    break

        pos += 0x28

    if cfg_pos is None:
        return None

    return cfg_pos, cfg_size


def extract_cfg_key(file_data, importcfgkey_func_pos):
    """Extract configuration data key using emulation"""

    pos = importcfgkey_func_pos

    # "sub esp, N" ?
    if (file_data[pos] != 0x83) or (file_data[pos + 1] != 0xEC):
        return None
    pos += 3

    # find "push 0F0000000h"
    pos2 = file_data.find(b'\x68\0\0\0\xF0', pos,
                          pos + MAX_IMPORTCFGKEY_CODE_SIZE)
    if pos2 < 0:
        return None

    code = file_data[pos : pos2]

    try:

        # Initialize emulator
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        code_size = (len(code) + 1 + 0xFFFF) & ~0xFFFF
        stack_addr = BASE_ADDR + code_size
        end_code_addr = BASE_ADDR + len(code)

        # Map memory for this emulation (dummy, code, stack)
        mu.mem_map(0, BASE_ADDR + code_size + STACK_SIZE)

        # Write code to memory
        mu.mem_write(BASE_ADDR, code)
        # Add nop to code
        mu.mem_write(end_code_addr, b'\x90')

        stack_pos = stack_addr + STACK_INIT_POS

        # Initialize stack registers
        mu.reg_write(UC_X86_REG_ESP, stack_pos)
        mu.reg_write(UC_X86_REG_EBP, stack_pos)

        # Emulate machine code in infinite time
        mu.emu_start(BASE_ADDR, end_code_addr + 1)

        # Read key
        return mu.mem_read(stack_pos, CFG_KEY_LEN)

    except UcError as e:

        print('Emu Error: %s' % e)
        return None


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
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    file_data = f.read()

cfg_pos = CFG_POS
if cfg_pos is None:

    # Get configuration data information
    cfg_info = get_cfg_info(file_data)
    if cfg_info is None:
        print('Error: Configuration data not found.')
        sys.exit(1)

    cfg_pos = cfg_info[0]
    cfg_size = cfg_info[1]

else:
    cfg_size = len(file_data) - cfg_pos

print('cfg data position: %08X' % cfg_pos)
print('cfg data size: %08X' % cfg_size)

importcfgkey_func_pos = IMPORTCFGKEY_FUNC_POS
print('import cfg key function position: %08X' % importcfgkey_func_pos)

# Get configuration data key
if HAVE_UNICORN:
    cfg_key = extract_cfg_key(file_data, importcfgkey_func_pos)
    if not cfg_key:
        print('Error:', 'Couldn\'t extract configuration data key')
        sys.exit(1)
else:
    # Load configuration data key from file
    with io.open('./cfg_key.bin', 'rb') as f:
        cfg_key = f.read(CFG_KEY_LEN)

cfg_data = file_data[cfg_pos : cfg_pos + cfg_size]

del file_data

# Create destination directory
dest_dir = os.path.abspath(os.path.dirname(file_name)) + '/cfg/'
mkdirs(dest_dir)

# Save configuration data key
save_data_to_file(dest_dir + 'cfg_key.bin', cfg_key)

cfg_num_entries, = struct.unpack_from('<L', cfg_data, 0)
print('cfg entries: %d' % cfg_num_entries)

# Decrypt and save configuration data entries
for i in range(cfg_num_entries):

    e_idx, e_pos, e_pos2, e_size = struct.unpack_from('<4H', cfg_data,
                                                      8 + i * CFG_ENTRY_SIZE)

    # Decrypt configuration data entry
    enc_e_data = cfg_data[e_pos : e_pos2]
    cipher = AES.new(cfg_key, AES.MODE_CBC, CFG_IV)
    e_data = cipher.decrypt(enc_e_data)

    # Save configuration data entry
    save_data_to_file(dest_dir + ('cfg_%02X.bin' % e_idx), e_data[:e_size])
