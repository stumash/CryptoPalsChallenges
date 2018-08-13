#!/usr/bin/env python3

from common_set02 import ecb_cbc_detection_oracle, aes_ecb_encrypt, pkcs7
from base64 import b64decode
import random

def main():
    encryptor = OracleEncryptor()

    """
    1. determine the keysize used by encryptor
    2. detect that encryptor is running in ecb mode
    3. determine the number of bytes in the unknown string
    4. determine the unknown string
    """

    keysize = discover_keysize(encryptor)
    assert(keysize == len(encryptor.AES_KEY))

    mode = ecb_cbc_detection_oracle(encryptor.encrypt(b'A'*keysize*2), keysize)
    assert(mode == 'ecb')

    unknown_bytes_len = discover_unknown_bytes_len(encryptor, keysize)
    assert(unknown_bytes_len == len(encryptor.UKNOWN_BYTES))

class OracleEncryptor():
    """
    This encryptor always encrypts using the same key after appending the
    same unknown text. We can represent this mathetmatically as

    AES_ECB( pkcs7(input-bytes || unknown-bytes, keysize) )

    where the AES key and the unknown-bytes are created once at object
    initialization.
    """
    def __init__(self):
        UKNOWN_STRING = (
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK"
        )
        self.UKNOWN_BYTES = b64decode(UKNOWN_STRING)

        KEYLEN  = 16 # initialize secret aes key
        self.AES_KEY = bytes(random.randint(0,255) for b in range(KEYLEN))

    def encrypt(self, bts: bytes) -> bytes:
        bts = pkcs7(bts + self.UKNOWN_BYTES, len(self.AES_KEY))
        return aes_ecb_encrypt(bts, self.AES_KEY)

def discover_keysize(encryptor: OracleEncryptor) -> int:
    """
    We know the keysize when we have fed 2*keysize identical
    bytes to the encryptor and the first and second keysize bytes
    of the resulting ciphertext are identical. So, start with keysize=1
    and keep going until the condition is met.
    """
    for keysize in range(1, 32): # 32 bytes = 256 bits = max key size
        bts = encryptor.encrypt(b'A' * keysize * 2)
        if bts[:keysize] == bts[keysize:keysize*2]:
            return keysize

def discover_unknown_bytes_len(encryptor: OracleEncryptor, keysize: int) -> int:
    """
    TODO: TODO: TODO: docsting
    """
    start_len = len(encryptor.encrypt(b''))
    for pad_len in range(1, 256):
        new_len = len(encryptor.encrypt(b'A' * pad_len))
        if new_len != start_len:
            return new_len - pad_len - (keysize - 1)

if __name__ == "__main__":
    main()