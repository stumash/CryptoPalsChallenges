#!/usr/bin/env python3

from common_set01 import hamming

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing large b64-encoded ciphertext resulting from
        repeating-xor''')
args = arg_parser.parse_args()

def main():
    pass

if __name__ == "__main__":
    main()
