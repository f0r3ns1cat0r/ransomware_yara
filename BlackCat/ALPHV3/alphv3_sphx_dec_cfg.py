import sys
import io
import os
import alphv3_sphx_crypt


MAX_CFG_SIZE = 0x40000


#
# Main
#
if len(sys.argv) != 3:
    print('Usage:', os.path.basename(sys.argv[0]), 'keyfile cfgfile')
    sys.exit(0)

key_filename = sys.argv[1]
cfg_filename = sys.argv[2]

with io.open(key_filename, 'rb') as f:
    key = f.read(alphv3_sphx_crypt.AES_KEY_SIZE)

with io.open(cfg_filename, 'rb') as f:

    cfg_size = int.from_bytes(f.read(4), byteorder='big', signed=False)
    if not (0 < cfg_size < MAX_CFG_SIZE - 4):
        raise Exception('Invalid cfg data size')

    print('cfg data size: ' + str(cfg_size))
    enc_cfgdata = f.read(cfg_size)

cfgdata = alphv3_sphx_crypt.aes_decrypt(enc_cfgdata, key)

new_filename = cfg_filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(cfgdata)