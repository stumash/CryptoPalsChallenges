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

    pad = keysize - (preamble_size % keysize)
    inp = b'A' * (pad + keysize*2)
    mode = ecb_cbc_detection_oracle(encryptor.encrypt(inp), keysize)
    assert(mode == 'ecb')

    target_bytes_len = discover_target_bytes_len(encryptor, preamble_size, keysize)
    assert(target_bytes_len == len(encryptor.TARGET_BYTES))

    target_bytes = discover_target_bytes(encryptor, preamble_size, target_bytes_len, keysize)
    assert(target_bytes == encryptor.TARGET_BYTES)

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
    that differs between the two ciphpertexts is the start of the first block whose
    plaintext contains input bytes.
    """
    c1, c2 = encryptor.encrypt(b''), encryptor.encrypt(b'A')
    blk_start = next(i for i,(b1,b2) in enumerate(zip(c1, c2)) if b1 != b2)
    # blk_start is the index of the first byte of the first ciphertext block whose
    # plaintext contains bytes from the encrypt function's input

    """
    Begin with input1 = b'' and input2 = b'A', and encrypt both. Append b'A' to both until
    the 'blk_start' byte of both ciphertexts is the same. This will happen when input1 is long
    enough that it ends at the end of a block and input2 ends one byte after.
    """
    for input_size in count():
        input1, input2 = map(lambda x: b'A'*x, (input_size, input_size+1))
        c1, c2 = map(encryptor.encrypt, (input1, input2))
        if c1[blk_start] == c2[blk_start]:
            # can fail if unlucky about contents encryptor's preamble bytes
            blk_end = next(i for i,(b1,b2) in enumerate(zip(c1, c2)) if b1 != b2)
            break

    keysize       = blk_end - blk_start
    preamble_size = blk_end - input_size

    return keysize, preamble_size

def discover_target_bytes_len(encryptor: OracleEncryptor, preamble_size: int, keysize: int) -> int:
    """
    This function has exactly the same logic as 'discover_unknown_bytes_len' from 12_code.py.

    However, there is the added complication that there is a constant preamble that is prepended
    to every plaintext (in addition to the appended target bytes) before encryption. Since the
    length of this preamble is known (argument preamble_size), we just subtract that length
    from the previously described formula for the return value.
    """
    start_len = len(encryptor.encrypt(b''))
    for pad_len in range(1, 256):
        new_len = len(encryptor.encrypt(b'A' * pad_len))
        if new_len != start_len:
            return new_len - (keysize - 1) - pad_len - preamble_size

def discover_target_bytes(encryptor: OracleEncryptor, preamble_size: int, target_size: int, keysize: int) -> bytes:
    """
    TODO: write this docstring
    """
    minimum_pad = b'A' * (keysize - (preamble_size % keysize))
    discovered_bytes = []

    for i in range(target_size):
        print(i)
        b_num = i % keysize # how deep into the current block is the byte we want
        pad   = minimum_pad + b'A' * (keysize - b_num - 1)

        bts     = pad + bytes(b for b in discovered_bytes)
        bts_blk = bts[-(keysize-1):] # the bytes in the same block as the byte we want

        d = {encryptor.encrypt(bts_blk + bytes([b]))[:keysize] : b for b in range(256)}

        blk_num = ((preamble_size + len(minimum_pad)) // keysize) + (i // keysize)
        enc     = encryptor.encrypt(pad)
        enc_blk = enc[blk_num*keysize:(blk_num+1)*keysize]

        discovered_bytes.append(d[enc_blk])

    return bytes(discovered_bytes)

if __name__ == "__main__":
    main()
