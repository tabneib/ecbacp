#!/usr/bin/python
import argparse
import re
import string
import sys
import textwrap

from termcolor import colored

# enc = __import__("ecbacp.encryption.noencrypt", fromlist=[''])


def exit_(msg):
    print(colored(msg, "red"))
    sys.exit()


class ACPAttack:

    def __init__(self, enc_=None, block_size=16,
                 probe_blocks=10, junk='A', debug=False):
        self.block_size = block_size
        self.probe_blocks = probe_blocks
        self.junk = junk
        self.debug = debug

        def encrypt(input_):
            try:
                c = enc_(input_)
                if c is None or c == '' or len(c) % self.block_size != 0:
                    exit_("[-] Encryption error. Program terminated.")
                else:
                    return c
            except:
                exit_("[-] Error when calling encryption function. "
                      "Program terminated.")
        self.encrypt = encrypt

    def detect_pattern(self):
        # We probe #blocksize blocks to determine the pattern
        probe_len = self.block_size * self.probe_blocks
        payload = self.junk * probe_len
        print(colored("\n[+] Ciphertext pattern detection started", "green"))
        if self.debug:
            print("\n[+] Payload:")
            print("\t\t" + "\n\t\t".join(textwrap.wrap(payload,
                                                       self.block_size << 1)))
            print("[+] Payload length: %d" % len(payload))
            print("[+] Sent %d blocks of self.junk \"%s\""
                  % (self.probe_blocks, self.junk))
        cipher_hex = self.encrypt(payload)
        pattern = "([0-9a-f]{" + str(self.block_size * 2) + "})\\1"
        ro = re.compile(pattern)
        if self.debug:
            print("[+] Ciphertext:")
            print("\t\t" + "\n\t\t".join(
                textwrap.wrap(cipher_hex, self.block_size << 1)))
            print("[+] Ciphertext length: %d" % (len(cipher_hex) >> 1))
            print("[+] Regex Pattern: %s" % pattern)
        # We look for some block_size-pattern that repeats at least 2 times
        s = ro.search(cipher_hex)
        if s and (s.start() >> 1) % self.block_size == 0:
            print("[+] Pattern detected: " + colored(s.group(1), "yellow"))
            print("[+] First occurrence (nibble): %d" % s.start())
            print("[+] First occurrence (byte):   %d" % (s.start() >> 1))
            return s.group(1), s.start() >> 1
        else:
            print("[-] No pattern in ciphertext found. Program terminated")
            sys.exit()

    def detect_prefix_length(self, pattern, prefix_aligned_len):
        print(colored("\n[+] Prefix length detection started", "green"))
        payload = self.junk * self.block_size
        max_len = self.probe_blocks * self.block_size
        ro = re.compile(pattern)
        if self.debug:
            print("[+] Regex pattern: %s" % pattern)
        for i in range(max_len):
            if self.debug:
                print("\n[+] Payloads sent so far: %d" % i)
                print("[+] Encrypting... Payload length: %d" % len(payload))
            cipher_hex = self.encrypt(payload)
            if self.debug:
                print("[+] Ciphertext length: %d" % (len(cipher_hex) >> 1))
            if ro.search(cipher_hex):
                # Prefix part is just padded with junk to be block-aligned
                print("[+] Prefix length: " +
                      colored(str(prefix_aligned_len-i), "yellow"))
                print("[+] Padding length for prefix: %d" % i)
                return prefix_aligned_len - i
            payload += self.junk
        print(colored("[-] Cannot detect prefix length. "
                      "Program terminated.", "red"))
        sys.exit()

    def detect_suffix_length(self, prefix_aligned_len, prefix_len):
        print(colored("\n[+] Suffix length detection started", "green"))
        # Set input such that the plain text up to the suffix is block-aligned
        payload = self.junk * (prefix_aligned_len - prefix_len) \
            + self.junk * self.probe_blocks * self.block_size
        # We next try to pad the suffix with self.junk such that it is
        # block-aligned. So maximal number of padding bytes is self.block_size
        # (= no padding at all!)
        max_len = self.block_size + 1
        init_cipher_len = len(self.encrypt(payload))
        for i in range(max_len):
            if self.debug:
                print("\n[+] Payload sent so far: %d" % i)
                print("[+] Encrypting... Payload length: %d" % len(payload))
            cipher_hex = self.encrypt(payload)
            if self.debug:
                print("[+] Ciphertext length: %d" % (len(cipher_hex) >> 1))
            if len(cipher_hex) > init_cipher_len:
                suffix_len = (init_cipher_len >> 1) \
                             - (prefix_aligned_len
                                + self.probe_blocks * self.block_size
                                + i % self.block_size)
                # If suffix length is already aligned with block length then
                # the we have to subtract the whole block padding
                if suffix_len % self.block_size == 0:
                    suffix_len -= self.block_size
                print("[+] Suffix length: "
                      + colored(str(suffix_len), "yellow"))
                print("[+] Padding length for suffix: "
                      + str(i % self.block_size))
                return suffix_len
            payload += self.junk
        print(colored("[-] Cannot detect suffix length. "
                      "Program terminated.", "red"))
        sys.exit()

    def brute_force_suffix(self, aligned_plen, plen, slen):
        print(colored("\n[+] Brute-forcing suffix started", "green"))
        suffix = ''
        for i in range(1, slen+1):
            print("[+] Guessing character %d" % i)
            offset = ((len(suffix) >> 4) << 4)
            # Get the expected value of suffix's preceding block
            p = self.junk * (aligned_plen - plen
                             + self.block_size + offset - i)
            c = self.encrypt(p)
            expect = c[(aligned_plen + offset)
                       << 1:(aligned_plen + self.block_size + offset) << 1]
            if self.debug:
                print("[+] Payload: %s" % p)
                print("[+] Cipher:")
                print("\t\t" + "\n\t\t".join(
                    textwrap.wrap(c, self.block_size << 1)))
                print("[+] Expect: %s" % expect)
            found = False
            for c in string.printable:
                p = self.junk * (offset + aligned_plen - plen
                                 + self.block_size - i) + suffix + c
                ct = self.encrypt(p)
                real = ct[(aligned_plen + offset)
                          << 1:(aligned_plen + self.block_size + offset) << 1]
                if self.debug:
                    print("\n[+] Trying: %s" % (suffix + c))
                    print("[+] Payload: %s" % p)
                    print("[+] Cipher:")
                    print("\t\t" + "\n\t\t".join(
                        textwrap.wrap(ct, self.block_size << 1)))
                    print("\n[+] Real:\t%s" % real)
                    print("[+] Expect:\t%s" % expect)
                if real == expect:
                    print("[+] Found one character: " + colored(c, "yellow"))
                    suffix += c
                    print("[+] Current suffix: %s" % suffix)
                    found = True
                    break
            if not found:
                print(colored("[-] Cannot find any character!", "red"))
                break
        return suffix


def main():
    global enc
    parser = argparse.ArgumentParser(
        description='''Adaptive chosen plaintext attack against ECB''')
    parser.add_argument("--enc", help='''encryption module to use. You can
    write your own encryption module that suites your use-case inside the
    package encryption (default: noencrypt)''',
                        type=str, default='noencrypt')
    parser.add_argument("--blocksize", help="ecb block size "
                                            "(default: 16 Bytes)",
                        type=int, choices=[8, 16, 24, 32], default=16)
    parser.add_argument("--junk", help="junk character to fill the payload "
                                       "(default: 'A')",
                        type=str, default='A')
    parser.add_argument("--probe", help="number of block used for probing "
                                        "(default: 10)",
                        type=int, default=10)
    parser.add_argument("-v", "--verbose",
                        help="verbose: display debug messages",
                        action="store_true")
    args = parser.parse_args()

    enc_module = __import__('encryption.' + args.enc, fromlist=[''])
    enc = enc_module.encrypt

    acp_attack = ACPAttack(
        enc, args.blocksize, args.probe, args.junk, args.verbose)
    p = acp_attack.detect_pattern()
    prefix_len = acp_attack.detect_prefix_length(p[0], p[1])
    suffix_len = acp_attack.detect_suffix_length(p[1], prefix_len)
    suffix = acp_attack.brute_force_suffix(p[1], prefix_len, suffix_len)
    print(colored("[OK]", "green"))
    if prefix_len > 0:
        print("[+] Prefix found, length: %d" % prefix_len)
    else:
        print("[+] No prefix found")  
    if suffix_len > 0:
        print("[+] Suffix found, length: %d" % suffix_len)
        if len(suffix) == 0:
            print("[+] Suffix content cannot be determined.")
        elif len(suffix) < suffix_len:
            print("[+] Part of the suffix content is determined:")
            print(' '*4 + colored(suffix, "yellow"))
        else:
            print("[+] The suffix content is successfully brute-forced:")
            print(' '*4 + colored(suffix, "yellow"))
    else:
        print("[+] No suffix found")


if __name__ == '__main__':
    main()
