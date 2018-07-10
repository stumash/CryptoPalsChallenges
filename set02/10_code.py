#!/usr/bin/env python3

from base64 import b64decode
from common_set02 import aes_cbc_encrypt, aes_cbc_decrypt

def main():
    with open('data/10_input.txt', 'r') as f:
        bts = b64decode(''.join(line.strip() for line in f))

    key = b'YELLOW SUBMARINE'
    iv  = b'0000000000000000'

    dec = aes_cbc_decrypt(bts, key, iv)
    print(len(bts), len(dec))

    assert(aes_cbc_encrypt(dec,key,iv) == bts)

    print(''.join(chr(b) for b in aes_cbc_decrypt(bts,key,iv)))

if __name__ == "__main__":
    main()
