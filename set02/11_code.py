#!/usr/bin/env python3

from typing import Tuple

from common_set02 import aes_cbc_encrypt, aes_ecb_encrypt, pkcs7
import random

KEYLEN = 16

def main():
    bts = b'X' * 42

    encrypted, used_mode = aes_cbc_or_ecb_encrypt_random_key(bts)

    detected_mode = ecb_cbc_detection_oracle(encrypted)

    s = 'used mode: {}, detected mode: {}'
    print(s.format(used_mode, detected_mode))

    assert(used_mode == detected_mode)

def aes_cbc_or_ecb_encrypt_random_key(bts: bytes) -> Tuple[bytes, str]:
    """
    bts --> random pad on both sides --> pkcs7 pad -->
    aes in cbc mode or ecb mode
    """
    bts = pkcs7( random_pad_both_sides(bts), KEYLEN )

    key = bytes(random.randint(0,255) for i in range(KEYLEN))
    if random.choice([True, False]):
        mode = 'cbc'
        iv  = b'0' * KEYLEN
        encrypted = aes_cbc_encrypt(bts, key, iv)
    else:
        mode = 'ecb'
        encrypted = aes_ecb_encrypt(bts, key)

    return encrypted, mode

def random_pad_both_sides(bts: bytes) -> bytes:
    pad_len = random.randint(5,11)
    return rand_bytes(pad_len) + bts + rand_bytes(pad_len)

def rand_bytes(size: int) -> bytes:
    return bytes(random.randint(0,255) for i in range(size))

def ecb_cbc_detection_oracle(bts: bytes) -> str:
    blks = [bts[i:i+KEYLEN] for i in range(0,len(bts),KEYLEN)]

    if len(blks) != len(set(blks)): return 'ecb'
    else: return 'cbc'

if __name__ == "__main__":
    main()
