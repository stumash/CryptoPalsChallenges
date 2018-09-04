#!/usr/bin/env python3

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
        self.AES_KEY = bytes(random.randint(0,256) for b in range(KEYLEN))

        RANDBYTESLEN = random.randint(1,256)
        self.RANDOM_BYTES = bytes(random.randint(0,256) for b in range(RANDBYTESLEN))

    def encrypt(self, bts: bytes) -> bytes:
        bts = pkcs7_pad(self.RANDOM_BYTES + bts + self.TARGET_BYTES, len(self.AES_KEY))
        return aes_ecb_encrypt(bts, self.AES_KEY)

def discover_keysize(encryptor: OracleEncryptor):
    """
    If the encryptor didn't prepend an unknown number of bytes before encrypting,
    we would be able to get the keysize just as we did in set02/12. Namely, we could
    feed an increasing number, n, of bytes into the encryptor. When the encryptor spits
    out two identical and adjacent blocks of ciphertext, each n/2 in length, we would
    know that n/2 is the keysize.

    However, since the encryptor prepends an unknown number of random bytes, p (where p
    may or may not be a multiple of the keysize), we cannot use the exact same strategy
    as we did in set02/12. Take the following example as explanation.

    ----EXAMPLE BEGIN------
    keysize = 8 bytes
    p = 6 bytes
    input = b'121234567812345678'
    
    Given that p=6, the first 8 bytes of ciphertext are the result of encrypting
    (6 random bytes || b'12'). The next pair of 8 bytes will be identical and the result
    of encrypting b'12345678' and b'12345678', respectively.
    ----EXAMPLE END------

    As we can see, 18 input bytes were given to the encryptor, yet the 2 identical blocks
    of ciphertext are the second two ciphertext blocks, and are 8 bytes in length. Note
    that 8 != 18/2.
    """
    return len(encryptor.AES_KEY)

if __name__ == "__main__":
    main()
