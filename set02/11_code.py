#!/usr/bin/env python3

from typing import Tuple

from common_set02 import aes_cbc_encrypt, aes_ecb_encrypt
from common_set02 import pkcs7_pad, ecb_cbc_detection_oracle
import random

KEYLEN = 16

def main():
    bts = b'X' * 42

    encrypted, used_mode = aes_cbc_or_ecb_encrypt_random_key(bts)

    detected_mode = ecb_cbc_detection_oracle(encrypted, KEYLEN)

    s = 'used mode: {}, detected mode: {}'
    print(s.format(used_mode, detected_mode))

    assert(used_mode == detected_mode)

def aes_cbc_or_ecb_encrypt_random_key(bts: bytes) -> Tuple[bytes, str]:
    bts = pkcs7_pad( random_pad_both_sides(bts), KEYLEN )
    key = bytes(random.randint(0,255) for i in range(KEYLEN))

    if random.choice([True, False]):
        mode = 'cbc'
        iv  = b'0' * KEYLEN
        enc = aes_cbc_encrypt(bts, key, iv)
    else:
        mode = 'ecb'
        enc = aes_ecb_encrypt(bts, key)

    return enc, mode

def random_pad_both_sides(bts: bytes) -> bytes:
    pad_len = random.randint(5,11)
    return rand_bytes(pad_len) + bts + rand_bytes(pad_len)

def rand_bytes(size: int) -> bytes:
    return bytes(random.randint(0,255) for i in range(size))

if __name__ == "__main__":
    main()
