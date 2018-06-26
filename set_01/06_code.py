#!/usr/bin/env python3

from base64 import b64decode
from common_set01 import hamming, eng_score, xor_decrypt, repeat_xor, chrify

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing large b64-encoded ciphertext resulting from
        repeating-xor''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bts = b64decode(''.join(line for line in f))

    keysize = min(range(2,40), key=lambda k: normalized_hamming(bts, k))

    tk      = [bts[start::keysize] for start in range(keysize)] # tk = _t_ranspose by _k_eysize

    key     = [max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k))) for bts in tk]

    dec     = repeat_xor(bts, key)

    print('key: {}, msg: {}'.format(*map(chrify, [key,dec])))

def normalized_hamming(bts: bytes, keysize: int):
    return hamming(bts[:keysize], bts[keysize:keysize*2]) / keysize

if __name__ == "__main__":
    main()
