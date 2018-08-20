
from binascii import hexlify
from base64 import b64decode
import random
import string

blocklen = 16 #128 Bits
prefix = 'ecb adaptive known plaintext atk' # 32 B
suffix = 'https://tabneib.github.io'        # 25 B
def encrypt(input_):
    c = (prefix + input_ + suffix).encode('ascii')
    padlen = blocklen - (len(c) % blocklen)
    if padlen:
        c += padlen * padlen.to_bytes(1,byteorder='big')
    else:
        c += blocklen * b'\x10'
    return hexlify(c).decode('ascii')
    
       
