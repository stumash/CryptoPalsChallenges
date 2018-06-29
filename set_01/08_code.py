#!/usr/bin/env python3

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing lines of hex-encoded ciphertext, one
        of which was produced by AES encryption in ECB mode''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        btss = [bytes.fromhex(line.strip()) for line in f]

if __name__ == "__main__":
    main()
