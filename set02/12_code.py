#!/usr/bin/env python3

from common_set02 import ecb_cbc_detection_oracle
from common_set02 import aes_ecb_encrypt, pkcs7

import random

KEYLEN  = 128
AES_KEY = bytes(random.randint(0,255) for i in range(KEYLEN))

def main():
    DISCOVERED_KEYLEN = 0

    for i in range(1, 256*2)): # max keylen is 256
        bts = b'A' * i
        enc = pkcs7_and_aes_ecb_encrypt(bts)

        try:
            if 'ecb' == ecb_cbc_detection_oracle(enc, i):
                DISCOVERED_KEYLEN = i
        except: pass

    if DISCOVERED_KEYLEN == 0: return

def pkcs7_and_aes_ecb_encrypt(bts: bytes) -> bytes:
    bts = pkcs7(bts, KEYLEN)
    return aes_ecb_encrypt(bts, AES_KEY)

if __name__ == "__main__":
    main()
