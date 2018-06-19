import os.path as osp
from collections import defaultdict
from functools import lru_cache
from itertools import cycle

def eng_score(s: str):
    eng_freq = _get_eng_freq()
    return sum(eng_freq[c] for c in s.lower())

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

def xor_decrypt(bts: bytes, k: int) -> str:
    return ''.join(chr(b^k) for b in bts)

def repeat_xor(bts: bytes, key: bytes) -> str:
    return bytes(b^k for b,k in zip(bts, cycle(key))).hex()

def hamming(s1: str, s2: str) -> int:
    """
    For two strings s1 and s2, count the number of
    bits that are different
    """
    assert(len(s1) == len(s2))
    return sum(_count_ones(ord(c1)^ord(c2)) for c1,c2 in zip(s1,s2))

@lru_cache(maxsize=256)
def _count_ones(n: int):
    if n == 0: return 0
    return n%2 + _count_ones(n//2)
