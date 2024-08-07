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
import uuid
import hashlib
import binascii


ID_LEN = 8
PASSWORD_LEN = 40


def generate_id() -> str:
    """Get victim ID"""

    # Get MAC-address number
    mac_num = uuid.getnode()

    mac = hex(mac_num).replace('0x', '').upper()
    mac = '-'.join([mac[2 * i : 2 * (i + 1)] for i in range(6)])

    h = hashlib.sha224()
    h.update(mac.encode())
    digest = h.hexdigest()

    return digest[:ID_LEN].upper()


#
# Main
#

# Generate password
password = binascii.hexlify(os.urandom(PASSWORD_LEN)).decode()
print('password:', password)

# Victim ID
victim_id = generate_id()
print('victim id:', victim_id)

with io.open(victim_id + '.txt', 'wt') as f:
    f.write('\n\t' + victim_id + '\n\t' + password)
