#!/usr/bin/env python3

from common_set01 import eng_score, xor_decrypt, chrify

def main():
    with open('data/03_input.txt', 'r') as f:
        bts = bytes.fromhex(next(line.strip() for line in f))

    key = max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k)))

    dec = chrify(xor_decrypt(bts, key))

    print("key: {}\nmsg: '{}'".format(key, dec))

if __name__ == "__main__":
    main()
