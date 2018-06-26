#!/usr/bin/env python3

from common_set01 import eng_score, xor_decrypt, chrify

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''contains one hex string''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bts = bytes.fromhex(next(line.strip() for line in f))

    key = max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k)))
    dec = chrify(xor_decrypt(bts, key))

    print("key: {}, msg: '{}'".format(key, dec))

if __name__ == "__main__":
    main()
