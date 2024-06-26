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

import struct


MASK32 = 0xFFFFFFFF

XXH_PRIME32_1 = 0x9E3779B1
XXH_PRIME32_2 = 0x85EBCA77
XXH_PRIME32_3 = 0xC2B2AE3D
XXH_PRIME32_4 = 0x27D4EB2F
XXH_PRIME32_5 = 0x165667B1

add32 = lambda x, y: (x + y) & MASK32

sub32 = lambda x, y: (x - y) & MASK32

mul32 = lambda x, y: (x * y) & MASK32

rol32 = lambda v, s: ((v << s) & MASK32) | ((v & MASK32) >> (32 - s))

xxh32_round = lambda v, n: \
    mul32(rol32(add32(v, mul32(n, XXH_PRIME32_2)), 13), XXH_PRIME32_1)


def xxhash32(data: bytes, seed: int) -> int:
    """Compute xxHash32"""

    seed &= MASK32

    i = 0

    if len(data) >= 16:

        v1 = (seed + XXH_PRIME32_1 + XXH_PRIME32_2) & MASK32
        v2 = add32(seed, XXH_PRIME32_2)
        v3 = seed
        v4 = sub32(seed, XXH_PRIME32_1)

        while i + 16 <= len(data):
            n1, n2, n3, n4 = struct.unpack_from('<4L', data, i)
            v1 = xxh32_round(v1, n1)
            v2 = xxh32_round(v2, n2)
            v3 = xxh32_round(v3, n3)
            v4 = xxh32_round(v4, n4)
            i += 16

        h = rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12) + rol32(v4, 18)
        h &= MASK32

    else:

        h = add32(seed, XXH_PRIME32_5)

    h = add32(h, len(data))

    while i + 4 <= len(data):
        n, = struct.unpack_from('<L', data, i)
        h = add32(h, mul32(n, XXH_PRIME32_3))
        h = mul32(rol32(h, 17), XXH_PRIME32_4)
        i += 4

    while i < len(data):
        h = add32(h, mul32(data[i], XXH_PRIME32_5))
        h = mul32(rol32(h, 11), XXH_PRIME32_1)
        i += 1

    h ^= h >> 15
    h = mul32(h, XXH_PRIME32_2)
    h ^= h >> 13
    h = mul32(h, XXH_PRIME32_3)
    return (h ^ (h >> 16))


if __name__ == '__main__':
    import sys
    import io
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    file_name = sys.argv[1]
    with io.open(file_name, 'rb') as f:
        data = f.read()

    h = xxhash32(data, 0)
    print(hex(h))
