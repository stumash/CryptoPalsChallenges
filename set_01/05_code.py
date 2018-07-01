#!/usr/bin/env python3

from common_set01 import repeat_xor, chrify

def main():
    with open('data/05_input.txt', 'r') as f:
        bts = bytes(f.read().strip(), 'us-ascii')

    result = repeat_xor(bts, b'ICE')

    with open('data/05_expected_output.txt', 'r') as f:
        expected_output = bytes.fromhex(next(line.strip() for line in f))
    assert(result == expected_output)

    print(result.hex())

if __name__ == "__main__":
    main()
