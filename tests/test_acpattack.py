import unittest
from ecbacp.ecbacp import ACPAttack
from binascii import hexlify


def gen_encrypt(block_len, prefix_len, suffix_len):
    """Generate custom noencrypt function for testing purpose"""
    prefix_ = 'p' * prefix_len
    suffix_ = 's' * suffix_len

    def encrypt(input_):
        c = (prefix_ + input_ + suffix_).encode('ascii')
        pad_len = block_len - (len(c) % block_len)
        if pad_len:
            c += pad_len * pad_len.to_bytes(1, byteorder='big')
        else:
            c += block_len * b'\x10'
        return hexlify(c).decode('ascii')
    return encrypt


class TestEncrypt(unittest.TestCase):
    """
    Test the encrypt function
    """
    def test_no_encrypt_function(self):
        acp_attack = ACPAttack()
        with self.assertRaises(SystemExit):
            acp_attack.encrypt("")

    def test_encrypt_empty_ciphertext(self):
        acp_attack = ACPAttack(lambda _: '')
        with self.assertRaises(SystemExit):
            acp_attack.encrypt("")

    def test_encrypt_unaligned_ciphertext(self):
        acp_attack = ACPAttack(lambda _: "ff" * (16 + 1))
        with self.assertRaises(SystemExit):
            acp_attack.encrypt("")


class TestDetectPattern(unittest.TestCase):
    """
    Test the detect_pattern function
    """
    def test_detect_pattern_unaligned_pattern(self):
        c = "b" * 6 + "a" * 64 + "b"*26
        acp_attack = ACPAttack(lambda _: c)
        with self.assertRaises(SystemExit):
            acp_attack.detect_pattern()

    def test_detect_pattern_unrepeated_pattern(self):
        c = "af" * 8 + "cd" * 8 + "eb" * 16 + "fa" * 16
        acp_attack = ACPAttack(lambda _: c)
        with self.assertRaises(SystemExit):
            acp_attack.detect_pattern()


class TestDetectPrefixLength(unittest.TestCase):
    def test_detect_prefix_length_found_prefix(self):
        c = "ae" * 16 + "ff" * 32 + "eb" * 16
        acp_attack = ACPAttack(lambda _: c)
        self.assertEqual(acp_attack.detect_prefix_length("ff"*16, 0), 0)

    def test_detect_prefix_length_not_found_prefix(self):
        c = "ae" * 16 + "fa" * 32 + "eb" * 16
        acp_attack = ACPAttack(lambda _: c)
        with self.assertRaises(SystemExit):
            acp_attack.detect_prefix_length("ff"*16, 0)


class TestDetectSuffixLength(unittest.TestCase):
    def test_detect_suffix_length_aligned_prefix_aligned_suffix(self):
        acp_attack = ACPAttack(gen_encrypt(16, 16, 16))
        self.assertEqual(acp_attack.detect_suffix_length(16, 16), 16)

    def test_detect_suffix_length_aligned_prefix_unaligned_suffix(self):
        acp_attack = ACPAttack(gen_encrypt(16, 16, 15))
        self.assertEqual(acp_attack.detect_suffix_length(16, 16), 15)


class TestBruteForceSuffix(unittest.TestCase):
    def test_brute_force_suffix_aligned_prefix_aligned_suffix(self):
        acp_attack = ACPAttack(gen_encrypt(16, 16, 16))
        self.assertEqual(acp_attack.brute_force_suffix(16, 16, 16), 16*'s')

    def test_brute_force_suffix_aligned_prefix_unaligned_suffix(self):
        acp_attack = ACPAttack(gen_encrypt(16, 16, 15))
        self.assertEqual(acp_attack.brute_force_suffix(16, 16, 15), 15*'s')

    def test_brute_force_suffix_unaligned_prefix_aligned_suffix(self):
        acp_attack = ACPAttack(gen_encrypt(16, 15, 16))
        self.assertEqual(acp_attack.brute_force_suffix(16, 15, 16), 16*'s')

    def test_brute_force_suffix_unaligned_prefix_unaligned_suffix(self):
        acp_attack = ACPAttack(gen_encrypt(16, 15, 15))
        self.assertEqual(acp_attack.brute_force_suffix(16, 15, 15), 15*'s')

