#!/usr/bin/env python3

from base64 import b64decode
from common_set01 import hamming, eng_score
from functools import partial

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing large b64-encoded ciphertext resulting from
        repeating-xor''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bts = b64decode(''.join(line.strip() for line in f))

    def normalized_hamming(keysize: int):
        s = ''.join(chr(b) for b in bts[:keysize*2])
        s1, s2 = s[:keysize], s[keysize:keysize*2]
        return hamming(s1, s2) / keysize

    probable_keysizes = sorted(range(2,40), key=normalized_hamming)[:3]

    # btss_pks = [[bytes(bts[i] for i in range(start,len(bts),pks)) for start in range(pks)]
                # for pks in probable_keysizes]

    # def key_score(btss: [bytes], pks: int, key: int):
        # return sum(eng_score(chr(b^key) for b in bts) for bts in btss) / pks

    # probable_keys = [max(range(256), key=partial(key_score, btss, pks))
                     # for btss,pks in zip(btss_pks,probable_keysizes)]

    # best_key = max(zip(probable_keys,10), key=)

if __name__ == "__main__":
    main()
