#!/usr/bin/env python3

import argparse
import string
from collections import defaultdict, Counter

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''contains one hex string''')
args = arg_parser.parse_args()

def main():
    cipher_text_bytes = get_input_bytes(args.input_file)

    mses = defaultdict(lambda: 2**32-1) # mean squared errors
    for key in map(ord, string.printable):
        s = bytes(b^key for b in cipher_text_bytes).decode('us-ascii').lower()

        if any(c not in string.printable for c in s): continue

        count     = Counter(s)
        freq      = defaultdict(int, {c: count[c]/len(s) for c in count})
        mses[key] = sum(abs(freq[c] - eng_freq[c])**2 for c in eng_freq) / len(eng_freq)

        # print(key, mses[key], s)

    best_key = min(mses, key=mses.get)
    s = bytes(b^best_key for b in cipher_text_bytes).decode('us-ascii')

    print(best_key, mses[best_key], s)

def get_input_bytes(filename):
    with open(filename, 'r') as f:
        line = next(line.strip() for line in f)
        return bytes.fromhex(line)

eng_freq = defaultdict(int)
with open('pride_and_prejudice.txt', 'r') as f:
    # count all occurence of characters
    length = 0
    for line in f:
        for c in line.strip():
            eng_freq[c] += 1
            length += 1
    # and divide by length of text
    for c in eng_freq:
        eng_freq[c] /= length

if __name__ == "__main__":
    main()
