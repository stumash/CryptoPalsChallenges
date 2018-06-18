import os.path as p
from collections import defaultdict

def get_eng_freq():
    big_book_name = 'pride_and_prejudice.txt'
    big_book_path = p.join(p.dirname(__file__), big_book_name)

    eng_freq = defaultdict(int)
    with open(big_book_path, 'r') as f:
        # count all occurence of each character
        length = 0
        for line in f:
            for c in line.strip():
                eng_freq[c] += 1
                length += 1
        # and divide by length of text
        for c in eng_freq:
            eng_freq[c] /= length
    return eng_freq
