#!/usr/bin/env python3

import argparse
import string
import sys
from collections import defaultdict,Counter

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
    help='''xxx''')
args = arg_parser.parse_args()

def main():
    cipher_text_bytes = get_input_bytes(args.input_file)

    # only try printable chars as keys
    mses = {key:2**32-1 for key in map(ord, string.printable)}
    for key in map(ord, string.printable):
        s = bytes(b^key for b in cipher_text_bytes).decode('us-ascii').lower()

        if any(c not in string.printable for c in s): continue

        counts = Counter(s)
        freqs  = {c: counts[s]/len(s) for c in s}
        mses[key] = sum(abs(freqs[c] - eng_c_to_freq[c]) for c in s)


    best_i,best_score = min(enumerate(mses), key=lambda tup: tup[1])
    print(best_i, best_score, bytes(b^best_i for b in cipher_text_bytes).decode('us-ascii'))

def get_input_bytes(filename):
    with open(filename, 'r') as f:
        line = next(line.strip() for line in f)
        return bytes.fromhex(line)

eng_c_to_freq = defaultdict(int, {
    "E": 12.02, "e": 12.02,
    "T":  9.10, "t":  9.10,
    "A":  8.12, "a":  8.12,
    "O":  7.68, "o":  7.68,
    "I":  7.31, "i":  7.31,
    "N":  6.95, "n":  6.95,
    "S":  6.28, "s":  6.28,
    "R":  6.02, "r":  6.02,
    "H":  5.92, "h":  5.92,
    "D":  4.32, "d":  4.32,
    "L":  3.98, "l":  3.98,
    "U":  2.88, "u":  2.88,
    "C":  2.71, "c":  2.71,
    "M":  2.61, "m":  2.61,
    "F":  2.30, "f":  2.30,
    "Y":  2.11, "y":  2.11,
    "W":  2.09, "w":  2.09,
    "G":  2.03, "g":  2.03,
    "P":  1.82, "p":  1.82,
    "B":  1.49, "b":  1.49,
    "V":  1.11, "v":  1.11,
    "K":  0.69, "k":  0.69,
    "X":  0.17, "x":  0.17,
    "Q":  0.11, "q":  0.11,
    "J":  0.10, "j":  0.10,
    "Z":  0.07, "z":  0.07
})

if __name__ == "__main__":
    main()
