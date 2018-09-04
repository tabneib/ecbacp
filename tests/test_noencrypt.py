import unittest
from ecbacp.encryption import noencrypt
from binascii import hexlify

prefix = noencrypt.prefix
prefix_hex = hexlify(prefix.encode('utf-8')).decode('utf-8')
suffix = noencrypt.suffix
suffix_hex = hexlify(suffix.encode('utf-8')).decode('utf-8')


class TestNoencrypt(unittest.TestCase):
    def test_prefix_length(self):
        self.assertEqual(len(noencrypt.prefix), 32)

    def test_prefix_length(self):
        self.assertEqual(len(noencrypt.suffix), 25)

    def test_noencrypt_empty_input(self):
        c = noencrypt.encrypt('')
        self.assertEqual(c, prefix_hex + suffix_hex + "07"*7)
