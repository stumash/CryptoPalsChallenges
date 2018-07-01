#!/usr/bin/env python3

from base64 import b64decode
from common_set01 import hamming, eng_score, xor_decrypt, repeat_xor, chrify
from statistics import mean

def main():
    with open('data/05_input.txt', 'r') as f:
        bts = b64decode(''.join(line for line in f))

    keysize = min(range(2,40), key=lambda k: normalized_hamming(bts, k))

    tk = [bts[start::keysize] for start in range(keysize)] # tk= t_ranspose by k_eysize

    key = [max(range(256), key=lambda k: eng_score(xor_decrypt(bts, k))) for bts in tk]

    msg = repeat_xor(bts, key)

    print('keysize: {}'.format(keysize))
    print('key: "{}"'.format(chrify(key)))
    print('message:\n{}'.format(chrify(msg)))

def normalized_hamming(bts: bytes, keysize: int):
    chunks = [bts[i:i+keysize] for i in range(0,len(bts)-keysize,keysize)]
    return mean(hamming(ch1,ch2) / keysize for ch1,ch2 in zip(chunks,chunks[1:]))

if __name__ == "__main__":
    main()
