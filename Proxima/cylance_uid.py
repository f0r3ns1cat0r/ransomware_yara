import base64
import struct


MACHINE_GUID = '873ba7f3-0986-40d0-97df-a1e48ced854f'


MASK32 = 0xFFFFFFFF

ror32 = lambda v, s: ((v & MASK32) >> s) | ((v << (32 - s)) & MASK32)


def get_wide_str_hash(s, n=0):
    """Get Unicode-string hash"""

    for ch in s:

        m = ord(ch)
        if (m >= 0x41) and (m <= 0x5A):
            m |= 0x20
        n = m + ror32(n, 13)

    return ror32(n, 13)


def get_uid(machine_guid):
    """Get U-ID"""

    h = 0xFFFFFFFF
    for _ in range(3):
        h = get_wide_str_hash(machine_guid, h)

    s = h.to_bytes(4, byteorder='little')
    s += s[::-1]

    uid = base64.b64encode(s)
    uid = bytearray(uid[:9])
    for i in range(len(uid)):
        # '+', '/', '='
        if (uid[i] == 0x2B) or (uid[i] == 0x2F) or (uid[i] == 0x3D):
            uid[i] = 0x7A  # 'z'

    return uid.decode()


#
# Main
#
uid = get_uid(MACHINE_GUID)
print('U-ID: \"%s\"' % uid)