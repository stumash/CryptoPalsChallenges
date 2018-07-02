#!/usr/bin/env python3

from collections import Counter

def main():
    with open('data/08_input.txt', 'r') as f:
        btss = [bytes.fromhex(line.strip()) for line in f]

    i,bts = max(enumerate(btss), key=unpackargs(lambda i,bts: ecb_detect(bts)))

    blocks = [bts[i:i+16] for i in range(0,len(bts)-16,16)]
    cnt = Counter(blocks)

    repeated,n_repeats = next((k,cnt[k]) for k in cnt if cnt[k] > 1)

    s = (
        'line number:           {}\n'
        'data:                \n{}\n'
        'repeated 16-bytes:     {}\n'
        'number of repetitions: {}'
    )
    print(s.format(i+1,bts.hex(),repeated.hex(),n_repeats))

def ecb_detect(bts):
    blocks = [bts[i:i+16] for i in range(0,len(bts)-16,16)]
    return len(blocks) != len(set(blocks))

def unpackargs(f):
    return lambda x: f(*x)

if __name__ == "__main__":
    main()
