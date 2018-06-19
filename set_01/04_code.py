#!/usr/bin/env python3

from common import eng_score, xor_decrypt

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing 60-character lines of text, one of which is
        english text encrypted with one-character XOR''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bl = [bytes.fromhex(line.strip()) for line in f]

    keys = [max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k))) for bts in bl]

    decs = [xor_decrypt(bts, k) for bts,k in zip(bl, keys)]

    best = max(decs, key=eng_score)

    print("'{}'".format(best))

if __name__ == "__main__":
    main()
