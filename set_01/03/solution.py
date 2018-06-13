#!/usr/bin/env python3

import argparse

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''xxx''')
args = arg_parser.parse_args()

def main():
    ctext = get_input_bytes(args.input_file)

    for i in range(256):
        key = bytes([i])[0]
        mtext = bytes(b^key for b in ctext)
        try:
            s = mtext.decode('us-ascii')
            first_word = s.split(' ')[0]
            if is_english_word(first_word):
                print(s)
        except:
            pass

def get_input_bytes(filename):
    with open(filename, 'r') as f:
        line = next(line.strip() for line in f)
        return bytes.fromhex(line)

def is_english_word(word):
    return True

if __name__ == "__main__":
    main()
