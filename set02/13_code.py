#!/usr/bin/env python3

from common_set02 import aes_ecb_encrypt, aes_ecb_decrypt, pkcs7_pad, pkcs7_unpad
from typing import Dict
import json
import string
import random
import re

def main():
    """
    First, test that profile_for(), query_string_parse(),
    encrypt(), and decrypt() all work correctly.
    """

    s = 'stu@mash.com'
    profile = profile_for(s)
    # print(s, profile)

    keysize = 16
    AES_KEY = bytes(random.randint(0,255) for i in range(keysize))
    enc = encrypt(profile.encode('utf-8'), AES_KEY)
    dec = decrypt(enc, AES_KEY)

    assert(dec.decode() == profile)
    # print(json.dumps(query_string_parse(profile)))

    """
    Then, encapsulate encrypt(pkcs7(profile_for(email_str), len(AES_KEY)), AES_KEY) in a
    single function, representing the adversary.
    """

    def make_profile_and_encrypt(s: str) -> bytes:
        p = profile_for(s)
        return encrypt(p.encode('utf-8'), AES_KEY)

    """
    Now, defeat the adversary

    We know that keysize=16, but we could have guessed it using techniques from set02/12
    """

    # input 'ABCDEFGHIJKLM' (len 13) encrypts the blocks
    # email=ABCDEFGHIJ KLM&uid=10&role= user\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    #
    # \---- blkA1 ---/ \---- blkA2 ---/ \---------------------- blkA3 -----------------/
    #
    # we want blkA1 and blkA2 so that we can later append ecb_aes('admin') instead of blkA3
    email0 = 'ABCDEFGHIJKLM'
    front_blk = make_profile_and_encrypt(email0)[:keysize*2]

    # input 'ABCDEFGHIJadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' encrypts the blocks
    # email=ABCDEFGHIJ admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b &uid=10^role=us ...
    #
    # \---- blkB1 ----/ \-------------------- blkB2 --------------------/ \--- blkB3 ---/ ...
    #
    # we want blkB2 so that we can append it to front_blk
    email1 = 'ABCDEFGHIJ' + 'admin'+'\x0b'*11
    admin_blk = make_profile_and_encrypt(email1)[keysize*1:keysize*2]

    handcrafted_ciphertext = front_blk + admin_blk

    # now test that it all worked: when the adversary decrypts, we inject an admin profile

    handcrafted_message = decrypt(handcrafted_ciphertext, AES_KEY).decode()
    injected_profile = query_string_parse(handcrafted_message)
    desired_profile  = {'email':email0, 'uid':'10', 'role':'admin'}

    assert(injected_profile == desired_profile)

def query_string_parse(s: str) -> Dict[str,str]:
    """
    convert 'x=1&y=2&z=3' to {'x': '1', 'y': '2', 'z': '3'}
    """
    return {k:v for [k,v] in ( kv.split('=') for kv in s.split('&') )}

def profile_for(email: str) -> str:
    """
    convert email to 'email=email&uid=10&role=user'
    """
    if '&' in email or '=' in email:
        raise ValueError('email cannot contain \'&\' or \'=\'')

    return f"email={email}&uid=10&role=user"

def encrypt(bts: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(bts, len(key))
    return aes_ecb_encrypt(padded, key)

def decrypt(bts: bytes, key: bytes) -> bytes:
    decrypted = aes_ecb_decrypt(bts, key)
    return pkcs7_unpad(decrypted)

if __name__ == "__main__":
    main()
