#!/usr/bin/env python3

from common_set02 import aes_ecb_encrypt, aes_ecb_decrypt, pkcs7_pad, pkcs7_unpad
from typing import Dict
import json
import string
import random

def main():
    s = 'stu@mash.com'
    profile = profile_for(s)
    print(s, profile)

    AES_KEY = bytes(random.randint(0,255) for i in range(16))
    enc = encrypt(profile.encode('utf-8'), AES_KEY)
    dec = decrypt(enc, AES_KEY)

    assert(dec.decode() == profile)
    print(json.dumps(query_string_parse(profile)))

    def make_profile_and_encrypt(s: str) -> bytes:
        p = profile_for(s)
        return encrypt(p.encode('utf-8'), AES_KEY)

    # we know the key length but we could just guess it if we didn't
    keysize = len(AES_KEY)

def query_string_parse(s: str) -> Dict[str,str]:
    return {k:v for [k,v] in ( kv.split('=') for kv in s.split('&') )}

def profile_for(s: str) -> str:
    if '&' in s or '=' in s:
        raise ValueError('email cannot contain \'&\' or \'=\'')

    return f"email={s}&uid=10&role=user"

def encrypt(bts: bytes, key: bytes) -> bytes:
    return aes_ecb_encrypt(pkcs7_pad(bts, len(key)), key)

def decrypt(bts: bytes, key: bytes) -> bytes:
    return pkcs7_unpad(aes_ecb_decrypt(bts, key))

if __name__ == "__main__":
    main()
