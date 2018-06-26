import os.path as osp
from collections import defaultdict
from functools import lru_cache
from itertools import cycle
from typing import Union

def eng_score(s: Union[str,bytes]):
    if type(s) == bytes: s = chrify(s)
    eng_freq = _get_eng_freq()
    return sum(eng_freq[c] for c in s.lower())

def chrify(it):
    return ''.join(chr(i) for i in it)

@lru_cache(maxsize=1)
def _get_eng_freq() -> {chr: int}:
    eng_freq = defaultdict(int)

    txtname = 'pride_and_prejudice.txt'
    txtpath = osp.join(osp.dirname(__file__), txtname)
    with open(txtpath, 'r') as f:
        length = 0
        for line in f:
            line = line.strip()
            for c in line:
                length += 1
                eng_freq[c] += 1
        for c in eng_freq:
            eng_freq[c] /= length

    return eng_freq

def xor_decrypt(bts: bytes, k: int) -> bytes:
    return bytes(b^k for b in bts)

def repeat_xor(bts: bytes, key: bytes) -> bytes:
    return bytes(b^k for b,k in zip(bts, cycle(key)))

def hamming(bts1: bytes, bts2: bytes) -> int:
    assert(len(bts1) == len(bts2))
    return sum(bin(b1^b2).count('1') for b1,b2 in zip(bts1,bts2))
