#!/usr/bin/env python3

from base64 import b64decode
from common_set01 import hamming, eng_score, xor_decrypt, repeat_xor, chrify
from statistics import mean

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing base64-encoded ciphertext produced by
        repeating-xor''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bts = b64decode(''.join(line for line in f))

    keysize = min(range(2,40), key=lambda k: normalized_hamming(bts, k))

    tk = [bts[start::keysize] for start in range(keysize)] # tk= t_ranspose by k_eysize

    key = [max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k))) for bts in tk]

    dec = repeat_xor(bts, key)

    print('keysize:\n{}'.format(keysize))
    print('key:\n{}'.format(chrify(key)))
    print('dec:\n{}'.format(chrify(dec)))

def normalized_hamming(bts: bytes, keysize: int):
    chunks = [bts[keysize*i:keysize*(i+1)] for i in range((len(bts)//keysize)-1)]
    return mean(hamming(chunks[i],chunks[i+1])/keysize for i in range(len(chunks)-1))

if __name__ == "__main__":
    main()
