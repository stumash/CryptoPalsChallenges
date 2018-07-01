#!/usr/bin/env python3

from base64 import b64encode

def main():
    with open('data/01_input.txt', 'r') as f:
        bts = bytes.fromhex(next(line.strip() for line in f))

    result = b64encode(bts).decode('utf-8')
    print(result)

    with open('data/01_expected_output.txt', 'r') as f:
        expected_output = next(line.strip() for line in f)
    assert(expected_output == result)

if __name__ == "__main__":
    main()
