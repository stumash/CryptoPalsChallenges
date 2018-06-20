#!/usr/bin/env python3

from base64 import b64decode
from common_set01 import hamming

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

    print(probable_keysizes)

if __name__ == "__main__":
    main()
