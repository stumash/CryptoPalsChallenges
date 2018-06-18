#!/usr/bin/env python3

import argparse
import string
from collections import defaultdict, Counter

# map chars to frequency in english text
from common import get_eng_freq

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing 60-character lines of text, one of which is
        english text encrypted with one-character XOR''')
args = arg_parser.parse_args()

def main():
    bl = get_input_bytes_list(args.input_file)

    best_msg, key_best_msg, mse_best_msg = "", 0, int(2**31-1)
    for b in bl:
        msg, key, mse = best_decrypt_attempt(b)
        print(msg, mse)
        if mse < mse_best_msg:
            best_msg, key_best_msg, mse_best_msg = msg, key, mse

    print(best_msg)
    print(mse_best_msg)

def get_input_bytes_list(filename):
    with open(filename, 'r') as f:
        return [bytes.fromhex(line.strip()) for line in f]

def best_decrypt_attempt(byt):
    mses = defaultdict(lambda: int(2**31-1))
    for key in range(256):
        try: s = bytes(b^key for b in byt).decode('us-ascii').lower()
        except: continue

        if any(c not in string.printable for c in s): continue

        count     = Counter(s)
        freq      = defaultdict(lambda: 0, {c:count[c]/len(s) for c in count})
        mses[key] = sum(abs(freq[c] - eng_freq[c])**2 for c in eng_freq) / len(eng_freq)

    if not mses: return "", 0, int(2**31-1)

    best_key = min(mses, key=mses.get)
    mse = mses[best_key]
    msg = bytes(b^key for b in byt).decode('us-ascii').lower()

    return msg, best_key, mse

eng_freq = get_eng_freq()

if __name__ == "__main__":
    main()
