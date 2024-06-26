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

import sys
import io
import os
import errno
import base64
import json


# Configuration data file position
CFG_POS = 0x00014C58
CFG_KEY = None # b'cerber'
CFG_KEY_LEN = 10
CFG_KEY_SPACE = 2
CFG_SPACE = 0 # 8

# Ransom note Base64 encoding
NOTE_IN_BASE64 = True


def rc4_ksa(key):
    """RC4 KSA"""
    key_len = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_prga(s):
    """RC4 PRGA"""
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[j], s[i] = s[i], s[j]
        yield s[(s[i] + s[j]) & 0xFF]


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

    f.seek(CFG_POS)

    if CFG_KEY is not None:
        key = CFG_KEY
    else:
        key = f.read(CFG_KEY_LEN)
        f.seek(CFG_POS + CFG_KEY_LEN + CFG_KEY_SPACE)

    cfg_size = int.from_bytes(f.read(4), byteorder='little')
    print('cfg data size: %d' % cfg_size)

    if CFG_SPACE != 0:
        f.seek(CFG_SPACE, 1)

    cfg_data = bytearray(f.read(cfg_size))

# Decrypt configuration data
s = rc4_ksa(key)
keystream = rc4_prga(s)

for i in range(len(cfg_data)):
    cfg_data[i] ^= next(keystream)

# Create destination directory
dest_dir = os.path.abspath(os.path.dirname(file_name)) + '/cfg/'
mkdirs(dest_dir)

save_data_to_file(dest_dir + 'cfg_data.bin', cfg_data)
print('cfg data saved to file.')

cfg_json = json.loads(cfg_data.strip(b'\0'))

# Save configuration data
with io.open(dest_dir + 'config.json', 'w', encoding='utf-8') as f:
    json.dump(cfg_json, f, ensure_ascii=False, indent=2)

# RSA public key
rsa_pub_key = base64.b64decode(cfg_json['global_public_key'])
save_data_to_file(dest_dir + 'rsa_pubkey.pem', rsa_pub_key)
print('RSA public key saved to file.')

# Ransom note templates
note_files = cfg_json.get('help_files')
if note_files is not None:
    note_name = note_files['files_name']
    for file_entry in note_files['files']:
        note_file_name = note_name + file_entry['file_extension']
        print('ransom note file:', note_file_name)
        note_file_body = file_entry.get('file_body')
        if note_file_body is not None:
            if NOTE_IN_BASE64:
                note_file_body = base64.b64decode(note_file_body)
            else:
                note_file_body = note_file_body.encode('utf-8')
            save_data_to_file(dest_dir + note_file_name, note_file_body)
            print('ransom note \"%s\" saved to file.' % note_file_name)

# Wallpaper
wallpaper = cfg_json.get('wallpaper')
if wallpaper is not None:
    wallpaper_text = wallpaper.get('text')
    if wallpaper_text is not None:
        save_data_to_file(dest_dir + 'wallpaper.txt',
                          wallpaper_text.encode('utf-8'))
        print('wallpaper text saved to file.')
