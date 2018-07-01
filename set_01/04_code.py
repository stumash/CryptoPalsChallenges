#!/usr/bin/env python3

from common_set01 import eng_score, xor_decrypt, chrify

def main():
    with open('data/04_input.txt', 'r') as f:
        btss = [bytes.fromhex(line.strip()) for line in f]

    keys = [max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k))) for bts in btss]

    decs = [xor_decrypt(bts, k) for bts,k in zip(btss, keys)]

    best = max(decs, key=eng_score)

    print("'{}'".format(chrify(best)))

if __name__ == "__main__":
    main()
