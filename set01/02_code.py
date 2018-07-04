#!/usr/bin/env python3

from common_set01 import chrify

def main():
    with open('data/02_input.txt', 'r') as f:
        [bts1, bts2] = [bytes.fromhex(line.strip()) for line in f]

    res = bytes(b1^b2 for b1,b2 in zip(bts1,bts2))

    with open('data/02_expected_output.txt', 'r') as f:
        expected_output = bytes.fromhex(next(line.strip() for line in f))
    assert(expected_output == res)

    print("in1: '{}'\nin2: '{}'\nres: '{}'".format(*map(chrify, [bts1,bts2,res])))

if __name__ == "__main__":
    main()
