#!/usr/bin/env python3

from base64 import b64encode

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''contains one line, a string of hex data''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        bts = bytes.fromhex(next(line.strip() for line in f))

    print(b64encode(bts).decode('utf-8'))

if __name__ == "__main__":
    main()
