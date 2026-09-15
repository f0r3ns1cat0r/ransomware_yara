import sys
import io
import os
import urllib.request
import urllib.error
import json


URL = 'https://decrypter.emsisoft.com/keys/stopdjvu/';


HEADERS = {
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)',
    'Content-Type': 'application/json'
}


def download_data(url):
    """Download data"""

    req = urllib.request.Request(url, headers=HEADERS)

    try:
        response = urllib.request.urlopen(req)

    except urllib.error.HTTPError as e:
        print('[Error] %s (%d)' % (e.reason, e.code))
        return None

    except urllib.error.URLError as e:
        print('[Error] ' + str(e.reason))
        return None

    return response.read()


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'id')
    sys.exit(0)

ident = sys.argv[1]
print('ID:', ident)

url = URL + ident

# Keys
key_data = download_data(url)
key_json = json.loads(key_data)
print('Keys:', len(key_json))
if len(key_json) > 0:
    with io.open(ident + '_key.json', 'w', encoding='utf-8') as f:
        json.dump(key_json, f, ensure_ascii = False, indent=2)
    sys.exit(0)

# Keystreams
keystream_data = download_data(url + '/keystreams')
keystream_json = json.loads(keystream_data)
print('Keystreams:', len(keystream_json))
if len(keystream_json) > 0:
    with io.open(ident + '_keystream.json', 'w', encoding='utf-8') as f:
        json.dump(keystream_json, f, ensure_ascii = False, indent=2)
