#!/usr/bin/env python3

from common_set01 import chrify

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''contains two hex-encoded lines of text''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        [bts1, bts2] = [bytes.fromhex(line.strip()) for line in f]

    res = chrify(b1^b2 for b1,b2 in zip(bts1,bts2))

    s1,s2 = tuple(map(chrify, [bts1,bts2]))

    print("in1: '{}'\nin2: '{}'\nres: '{}'".format(s1,s2,res))

if __name__ == "__main__":
    main()
