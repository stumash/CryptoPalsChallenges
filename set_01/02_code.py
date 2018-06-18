#!/usr/bin/env python3

import argparse

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''contains two hex-encoded lines of text''')
args = arg_parser.parse_args()

def main():
    b1,b2 = get_input_bytes(args.input_file) # len(b1) == len(b2)

    result = bytes(b1[i]^b2[i] for i in range(len(b1)))

    print('utf-8 decoded hex:\n', result.decode('utf-8'), sep='')
    print()
    print('raw hex:\n', result.hex(), sep='')

def get_input_bytes(filename):
    with open(filename, 'r') as f:
        lines = (line.strip() for line in f)
        line1 = next(lines)
        line2 = next(lines)
    return tuple(map(bytes.fromhex,[line1,line2]))

if __name__ == "__main__":
    main()
