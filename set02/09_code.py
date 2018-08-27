#!/usr/bin/env python3

from common_set02 import pkcs7

def main():
    bts_unpadded = b'YELLOW SUBMARINE'

    bts_padded = pkcs7_pad(bts_unpadded, 20)

    assert(bts_padded == b'YELLOW SUBMARINE\x04\x04\x04\x04')

    s = (
        'bts_unpadded: \'{}\'\n'
        'bts_padded:   \'{}\'\n'
    )
    print(s.format(bts_unpadded, bts_padded), end='')

if __name__ == "__main__":
    main()
