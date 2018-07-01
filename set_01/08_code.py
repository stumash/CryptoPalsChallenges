#!/usr/bin/env python3

from collections import Counter

import argparse
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing lines of hex-encoded ciphertext, one
        of which was produced by AES encryption in ECB mode (16-bit key)''')
args = arg_parser.parse_args()

def main():
    with open(args.input_file, 'r') as f:
        btss = [bytes.fromhex(line.strip()) for line in f]

    best_i,best_bts = max(enumerate(btss), key=lambda t: ecb_detect(t[1]))

    print("line number: {}\ndata: {}".format(best_i+1,best_bts.hex()))

def ecb_detect(bts):
    blocks = [bts[i:i+16] for i in range(0,len(bts)-16,16)]
    cnt = Counter(blocks)

    if len(blocks) != len(cnt):
        s = "repeated 16 bytes: {}\nnumber of repetitions: {}"
        print(next(s.format(k.hex(),cnt[k]) for k in cnt if cnt[k] > 1))

    return len(blocks) != len(cnt)

if __name__ == "__main__":
    main()
