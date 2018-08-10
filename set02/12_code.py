#!/usr/bin/env python3

from common_set02 import ecb_cbc_detection_oracle
from common_set02 import aes_ecb_encrypt, pkcs7
import random

UKNOWN_STRING = ( # string to decode
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)

B = b'X' # a random byte

KEYLEN  = 16 # initialize secret aes key
AES_KEY = bytes(random.randint(0,255) for b in range(KEYLEN))


def main(encryptor):
    """
    1. determine the keysize used by encryptor
    2. detect that encryptor is running in ecb mode
    3.
    """
    keysize = discover_keysize(encryptor)

    assert(ecb_cbc_detection_oracle(encryptor(B*keysize*2), keysize) == 'ecb')

    d = { encryptor(B*(keysize-1) + b): b for b in bytes(list(range(255))) }

def discover_keysize(encryptor) -> int:
    """
    Discover the key size of the encryptor by passing it a single random
    byte and checking the length of the encrypted output
    """
    return len(encryptor(B))

def pkcs7_and_aes_ecb_encrypt(bts: bytes) -> bytes:
    """
    Pad bts using pkcs7 then encrypt with aes
    """
    bts = pkcs7(bts, KEYLEN)
    return aes_ecb_encrypt(bts, AES_KEY)



if __name__ == "__main__":
    main(pkcs7_and_aes_ecb_encrypt)
