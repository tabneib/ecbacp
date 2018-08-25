#!/usr/bin/python
import os
import sys
import argparse
import re
import string
import textwrap
from binascii import hexlify
from base64 import b64decode
from termcolor import colored

enc = __import__("encryption.noencrypt", fromlist=[''])
debug = False
# block size in byte
blocksize = 16
probeblk = 10
junk = 'A'

def exit_(msg):
    print(colored(msg,"red"))
    sys.exit()

def encrypt(input_):
    try:
        c = enc.encrypt(input_)
        if (c == None):
            exit_("[-] Encryption error. Program terminated.")
        else:
            return c
    except:
        exit_("[-] Error when calling encryption function. Program terminated.")

        
def detect_pattern():
    # We probe #blocksize blocks to determine the pattern
    probelen = blocksize * probeblk
    payload = junk * probelen
    print(colored("\n[+] Ciphertext pattern detection started","green"))
    if (debug):
        print("\n[+] Payload:")
        print("\t\t" + "\n\t\t".join(textwrap.wrap(payload, blocksize<<1)))
        print("[+] Payload length: %d" %(len(payload)))
        print("[+] Sent %d blocks of junk \"%s\"" %(probeblk, junk))
    cipher_hex = encrypt(payload)
    pattern = "([0-9a-f]{" + str(blocksize * 2)  + "})\\1"
    ro = re.compile(pattern)
    if (debug):
        print("[+] Ciphertext:")
        print("\t\t" + "\n\t\t".join(textwrap.wrap(cipher_hex, blocksize<<1)))
        print("[+] Ciphertext length: %d" %(len(cipher_hex) >> 1))
        print("[+] Regex Pattern: %s" %(pattern))
    # We look for some blocksize-byte-pattern that repeats at least 2 times
    s = ro.search(cipher_hex)
    if (s):
        print("[+] Pattern detected: " + colored(s.group(1), "yellow"))
        print("[+] First occurence (nibble): %d" %(s.start())) 
        print("[+] First occurence (byte):   %d" %(s.start()>>1)) 
        return (s.group(1), s.start()>>1)
    else:
        print("[-] No pattern in ciphertext found. Program terminated")
        sys.exit()
        
def detect_prefix_length(pattern, prefix_aligned_len):
    print(colored("\n[+] Prefix length detection started","green"))
    payload = junk * blocksize
    maxLen = probeblk * blocksize
    ro = re.compile(pattern)
    if (debug):
        print("[+] Regex pattern: %s" %(pattern))
    for i in range(maxLen):
        if (debug):
            print("\n[+] Payloads sent sofar: %d" %(i))
            print("[+] Encrypting... Payload length: %d" %(len(payload))) 
        cipher_hex = encrypt(payload)
        if (debug):
            print("[+] Ciphertext length: %d" %(len(cipher_hex) >> 1))
        if (ro.search(cipher_hex)):
            # Prefix part is just padded with junk to be block-alligned
            print("[+] Prefix length: " + colored(str(prefix_aligned_len-i),"yellow"))
            print("[+] Padding length for prefix: %d" %(i))
            return (prefix_aligned_len - i)
        payload += junk 
    print(colored("[-] Cannot detect prefix length. Program terminated.","red"))
    sys.exit()
       
def detect_suffix_length(pattern, prefix_aligned_len, prefix_len):
    print(colored("\n[+] Suffix length detection started","green"))
    # Set input such that the plain text up to the suffix is block-alligned
    payload = junk * (prefix_aligned_len - prefix_len) + junk * probeblk * blocksize
    # We next try to pad the suffix with junk such that it is block-alligned
    # So maximal number of padding bytes is blocksize (= no padding at all!)
    maxLen = blocksize + 1
    init_cipher_len = len(encrypt(payload))
    for i in range(maxLen):
        if (debug):
            print("\n[+] Payload sent sofar: %d" %(i))
            print("[+] Encrypting... Payload length: %d" %(len(payload))) 
        cipher_hex = encrypt(payload)
        if (debug):
            print("[+] Ciphertext length: %d" %(len(cipher_hex) >> 1))
        if (len(cipher_hex) > init_cipher_len):
            suffix_len = (init_cipher_len >> 1) - (prefix_aligned_len + probeblk*blocksize + i%blocksize)
            print("[+] Suffix length: " + colored(str(suffix_len),"yellow"))
            print("[+] Padding length for suffix: " + str(i%blocksize))
            return suffix_len
        payload += junk
    print(colored("[-] Cannot detect suffix length. Program terminated.","red"))
    sys.exit()

def bruteforce_suffix(pa_len, p_len, s_len):
    print(colored("\n[+] Bruteforcing suffix started","green")) 
    suffix = ''
    for i in range(1,s_len+1):
        print("[+] Guessing character %d" %(i))
        offset = ((len(suffix)>>4)<<4)
        # Get the expected value of suffix's preceeding block
        p = junk * (pa_len - p_len + blocksize + offset - i)
        c = encrypt(p)
        expect = c[(pa_len + offset)<<1:(pa_len+blocksize+offset)<<1]
        if (debug):
            print("[+] Payload: %s" %(p))
            print("[+] Cipher:")
            print("\t\t" + "\n\t\t".join(textwrap.wrap(c, blocksize<<1)))
            print("[+] Expect: %s" %(expect))
        found = False
        for c in string.printable:
            p = junk * (offset + pa_len - p_len + blocksize - i) +suffix + c
            ct = encrypt(p)
            real = ct[(pa_len+offset)<<1:(pa_len+blocksize+offset)<<1]
            if(debug):
                print("\n[+] Trying: %s" %(suffix + c))
                print("[+] Payload: %s" %(p))
                print("[+] Cipher:")
                print("\t\t" + "\n\t\t".join(textwrap.wrap(ct, blocksize<<1)))
                print("\n[+] Real:\t%s" %(real))
                print("[+] Expect:\t%s" %(expect))
            if (real == expect):
                print("[+] Found one character: " + colored(c,"yellow"))
                suffix += c
                print("[+] Current suffix: %s" %(suffix))
                found = True
                break
        if (not found):
            print(colored("[-] Cannot find any character!","red"))
            break
    return suffix

def main():
    global enc
    global debug
    global blocksize
    global probeblk 
    global junk 
    parser = argparse.ArgumentParser(description = '''Adaptive chosen plaintext attack
                                                      against ECB''')
    parser.add_argument("--enc", help='''encryption module to use.
                                         You can write your own encryption module
                                         that suites your use-case inside the package
                                         encryption (default: noencrypt)''', 
                        type=str, default='noencrypt')
    parser.add_argument("--blocksize", help="ecb block size (default: 16 Bytes)", 
                        type=int, choices=[8,16,24,32], default=16)
    parser.add_argument("--junk", help="junk character to fill the payload (default: 'A')",
                        type=str, default='A')
    parser.add_argument("--probe", help="number of block used for probing (default: 10)",
                        type=int, default=10)
    parser.add_argument("-v", "--verbose", help="verbose: display debug messages", action="store_true")
    args = parser.parse_args()

    enc = __import__('encryption.' + args.enc, fromlist=[''])
    debug = args.verbose
    blocksize = args.blocksize
    probeblk = args.probe
    junk = args.junk
    
    p = detect_pattern()
    prefix_len = detect_prefix_length(p[0],p[1])
    suffix_len = detect_suffix_length(p[0],p[1],prefix_len)
    suffix = bruteforce_suffix(p[1], prefix_len, suffix_len)
    print(colored("[OK]","green"))
    if (prefix_len > 0):
        print("[+] Prefix found, length: %d" %(prefix_len))
    else:
        print("[+] No prefix found")  
    if (suffix_len > 0):
        print("[+] Suffix found, length: %d" %(suffix_len))
        if (len(suffix) == 0):
            print("[+] Suffix content cannot be determined.")
        elif (len(suffix) < suffix_len):
            print("[+] Part of the suffix content is determined:")
            print(' '*4 + colored(suffix,"yellow"))
        else:
            print("[+] The suffix content is successfully brute-forced:")
            print(' '*4 + colored(suffix,"yellow"))
    else:
        print("[+] No subfix found")  


if __name__ == '__main__':
    main()

