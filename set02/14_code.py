#!/usr/bin/env pythona

from common_set02 import aes_ecb_encrypt, pkcs7_pad

def main():
    encryptor = OracleEncryptor()

    """
    1. determine the keysize used by the encryptor
    2. detect that encryptor is running in ecb mode
    3. determine the number of bytes in the unknown string
    4. determine the unknown string
    """

    keysize = discover_keysize(encryptor)
    assert(keysize == len(encryptor.AES_KEY))

    print('done')

class OracleEncryptor():
    """
    When instantiated, this encryptor generates
    1. some RANDOM BYTES to always prepend to all plaintext before encryption
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

        RANDBYTESLEN = random.randint(1,255)
        self.RANDOM_BYTES = bytes(random.randint(0,255) for b in range(RANDBYTESLEN))

    def encrypt(self, bts: bytes) -> bytes:
        bts = pkcs7_pad(self.RANDOM_BYTES + bts + self.TARGET_BYTES, len(self.AES_KEY))
        return aes_ecb_encrypt(bts, self.AES_KEY)

def discover_keysize(encryptor: OracleEncryptor):
    pass

if __name__ == "__main__":
    main()
