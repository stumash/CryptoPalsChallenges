import os.path as osp
from collections import defaultdict
from functools import lru_cache
from itertools import cycle

@lru_cache(maxsize=1)
def _get_eng_freq():
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

def eng_score(s: str):
    eng_freq = _get_eng_freq()
    return sum(eng_freq[c] for c in s.lower())

def xor_decrypt(bts: bytes, k: int) -> str:
    return ''.join(chr(b^k) for b in bts)

def repeat_xor(bts: bytes, key: bytes) -> str:
    return bytes(b^k for b,k in zip(bts, cycle(key))).hex()
