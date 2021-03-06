#!/usr/bin/env python3

from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from common_set01 import chrify

def main():
    with open('data/07_input.txt', 'r') as f:
        bts = b64decode(''.join(line for line in f))

    backend = default_backend()
    key     = b'YELLOW SUBMARINE'

    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    msg = decryptor.update(bts) + decryptor.finalize()

    print(chrify(msg))

if __name__ == "__main__":
    main()
