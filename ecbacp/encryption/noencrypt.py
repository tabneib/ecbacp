from binascii import hexlify

block_len = 16  # 128 Bits
prefix = 'ecb adaptive chosen plaintxt atk'  # 32 B
suffix = 'https://tabneib.github.io'         # 25 B


def encrypt(input_):
    c = (prefix + input_ + suffix).encode('ascii')
    pad_len = block_len - (len(c) % block_len)
    if pad_len:
        c += pad_len * pad_len.to_bytes(1, byteorder='big')
    else:
        c += block_len * b'\x10'
    return hexlify(c).decode('ascii')
