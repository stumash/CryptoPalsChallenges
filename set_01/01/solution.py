#!/usr/bin/env python3

import argparse
from collections import ChainMap
from base64 import b64encode

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''contains one line, a string of hex data''')
args = arg_parser.parse_args()

def main():
    hex_str = get_input_str(args.input_file)

    # every two hex digits in the str become a single byte
    hex_bytes = bytes.fromhex(hex_str)

    # every 3 bytes converts to 4 bytes according to base64
    b64_enc_bytes = b64encode(hex_bytes)

    print(b64_enc_bytes.decode('utf-8'))

def get_input_str(filename):
    with open(filename, 'r') as f:
        return next(line.strip() for line in f)

if __name__ == "__main__":
    main()
