#!/usr/bin/env pythona

from common_set02 import aes_ecb_encrypt, pkcs7_pad

def main():
    encryptor = OracleEncryptor()

    print('done')

class OracleEncryptor():
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

if __name__ == "__main__":
    main()
