#!/usr/bin/env python3

from common_set01 import repeat_xor

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing two-line msg to enrypt''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bts = bytes(f.read().strip(), 'us-ascii')

    print(repeat_xor(bts, b'ICE'))

if __name__ == "__main__":
    main()
