#!/usr/bin/env python3

from common_set02 import aes_ecb_encrypt, pkcs7_pad, ecb_cbc_detection_oracle
from base64 import b64decode
from itertools import count
from typing import Tuple
import random

"""
NOTE: this program involves some randomness. It can fail randomly, though it fails
much less often than it succeeds
"""

def main():
    encryptor = OracleEncryptor()

    """
    1. determine the keysize and preamble size used by encryptor
    2. detect that the encryptor is running in ecb mode
    3. determine the number of bytes in the unknown string TODO
    4. determine the unknown string TODO
    """

    keysize, preamble_size = discover_keysize_and_preamble_size(encryptor)
    assert(keysize == len(encryptor.AES_KEY))
    assert(preamble_size == len(encryptor.PREAMBLE_BYTES))

    mode = ecb_cbc_detection_oracle(encryptor.encrypt(), keysize)
    assert(mode == 'ecb')

    print('done')

class OracleEncryptor():
    """
    When instantiated, this encryptor generates
    1. some PREAMBLE BYTES to always prepend to all plaintext before encryption
    2. a random AES KEY to always use for encryption
    During instantiation, this encryptor also initializes
    3. some TARGET BYTES to always append to all plaintext before encryption

    This encryptor performs the following function
    AES_ECB( pkcs7_pad(random bytes||input bytes||target bytes) )
    """
    def __init__(self):
        TARGET_STRING = (
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK"
        )
        self.TARGET_BYTES = b64decode(TARGET_STRING)

        KEYLEN = 16
        self.AES_KEY = bytes(random.randint(0,255) for b in range(KEYLEN))

        PREAMBLE_LEN = random.randint(1,256*4)
        self.PREAMBLE_BYTES = bytes(random.randint(0,255) for b in range(PREAMBLE_LEN))

    def encrypt(self, bts: bytes) -> bytes:
        bts = pkcs7_pad(self.PREAMBLE_BYTES + bts + self.TARGET_BYTES, len(self.AES_KEY))
        return aes_ecb_encrypt(bts, self.AES_KEY)

def discover_keysize_and_preamble_size(encryptor: OracleEncryptor) -> Tuple[int,int]:
    """
    Get ciphertext c1 from input b'' and ciphertext c2 from input b'A'. The first byte
    that differs between the two ciphpertexts is the beginning of the first block whose
    plaintext contains input bytes.
    """
    c1, c2 = encryptor.encrypt(b''), encryptor.encrypt(b'A')
    start = next(i for i,(b1,b2) in enumerate(zip(c1, c2)) if b1 != b2)

    # TODO: fix this comment
    """
    Keep increasing input input_size by 1 byte until the byte at index 'start' of the ciphertext
    stops changing. When it stops changing, it means the last input was
    """
    for input_size in count():
        c1,c2 = encryptor.encrypt(b'A'*input_size), encryptor.encrypt(b'A'*(input_size+1))
        if c1[start] == c2[start]:
            # can fail. probability of failure ~= 1/256
            end = next(i for i,(b1,b2) in enumerate(zip(c1, c2)) if b1 != b2)
            break

    keysize       = end - start
    preamble_size = end - input_size

    return keysize, preamble_size

if __name__ == "__main__":
    main()
