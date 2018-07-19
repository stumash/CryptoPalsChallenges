#!/usr/bin/env python3

from typing import Tuple

from common_set02 import aes_cbc_encrypt, aes_ecb_encrypt, pkcs7
import random

KEYLEN = 16

def main():
    bts = b'SOME RandOm T3xt. EnKryPT TH15 4 GRATE G00d!'

    encrypted, used_cbc_mode = aes_cbc_or_ecb_encrypt_random_key(bts)

    detected_cbc_mode = cbc_detection_oracle(encrypted)

    s = "used_cbc_mode: {}, detected_cbc_mode: {}"
    print(s.format(used_cbc_mode, detected_cbc_mode))
    assert(used_cbc_mode == detected_cbc_mode)

def aes_cbc_or_ecb_encrypt_random_key(bts: bytes) -> Tuple[bytes, bool]:
    bts = random_pad_left_right(bts)
    bts = pkcs7(bts, KEYLEN)
    key = bytes(random.randint(0,255) for i in range(KEYLEN))

    use_cbc = random.choice([True, False])
    if use_cbc:
        iv  = b'0' * KEYLEN
        encrypted = aes_cbc_encrypt(bts, key, iv)
    else:
        encrypted = aes_ecb_encrypt(bts, key)

    return encrypted, use_cbc

def random_pad_left_right(bts: bytes) -> bytes:
    pad_len = random.randint(5,11)
    l_pad = bytes(random.randint(0,255) for i in range(pad_len))
    r_pad = bytes(random.randint(0,255) for i in range(pad_len))
    return l_pad + bts + r_pad

def cbc_detection_oracle(bts: bytes) -> bool:
    blks = [bts[i:i+KEYLEN] for i in range(0,len(bts),KEYLEN)]
    return len(blks) != len(set(blks))

if __name__ == "__main__":
    main()
