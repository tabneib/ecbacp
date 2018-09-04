import requests
from urllib.parse import urlparse, parse_qs, unquote
from binascii import hexlify
from base64 import b64decode
from termcolor import colored

url = "http://natas28.natas.labs.overthewire.org/index.php"
headers = {"Authorization":
           "Basic bmF0YXMyODpKV3dSNDM4d2tnVHNOS0JiY0pvb3d5eXNkTTgyWWplRg=="}


def encrypt(input_):
    r = requests.post(url, headers=headers, data={"query": input_})
    if r.status_code != 200:
        print(colored("[-] Connection error. Status Code: "
                      + str(r.status_code), "red"))
        return None
    else:    
        resp_url = urlparse(r.url)
        cipher_b64 = unquote(parse_qs(resp_url.query)["query"][0])
        if cipher_b64:
            cipher = b64decode(cipher_b64)
            cipher_hex = hexlify(cipher).decode('ascii')
            return cipher_hex 
        else:
            print(colored("[-] Unrecognizable URL format", "red"))
            return None 
