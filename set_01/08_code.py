#!/usr/bin/env python3

from collections import Counter

def main():
    with open('data/08_input.txt', 'r') as f:
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
