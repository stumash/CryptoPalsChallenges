#!/usr/bin/env python3

from common_set02 import ecb_cbc_detection_oracle, aes_ecb_encrypt, pkcs7_pad
from base64 import b64decode
import random

def main():
    encryptor = OracleEncryptor()

    """
    1. determine the keysize used by encryptor
    2. detect that encryptor is running in ecb mode
    3. determine the number of bytes in the unknown string
    4. determine the unknown string
    """

    keysize = discover_keysize(encryptor)
    assert(keysize == len(encryptor.AES_KEY))

    mode = ecb_cbc_detection_oracle(encryptor.encrypt(b'A'*keysize*2), keysize)
    assert(mode == 'ecb')

    unknown_bytes_len = discover_unknown_bytes_len(encryptor, keysize)
    assert(unknown_bytes_len == len(encryptor.UNKNOWN_BYTES))

    unknown_bytes = discover_unknown_bytes(encryptor, keysize, unknown_bytes_len)
    assert(unknown_bytes == encryptor.UNKNOWN_BYTES)

    print(unknown_bytes.decode())

class OracleEncryptor():
    """
    This encryptor always encrypts using the same key after appending the
    same unknown text. We can represent this mathetmatically as

    AES_ECB( pkcs7_pad(input-bytes||unknown-bytes) )

    where the AES key and the unknown-bytes are created once at object
    initialization. ('||' is the concatenation operator)
    """
    def __init__(self):
        UNKNOWN_STRING = (
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK"
        )
        self.UNKNOWN_BYTES = b64decode(UNKNOWN_STRING)

        KEYLEN  = 16 # initialize secret aes key
        self.AES_KEY = bytes(random.randint(0,255) for b in range(KEYLEN))

    def encrypt(self, bts: bytes) -> bytes:
        bts = pkcs7_pad(bts + self.UNKNOWN_BYTES, len(self.AES_KEY))
        return aes_ecb_encrypt(bts, self.AES_KEY)

def discover_keysize(encryptor: OracleEncryptor) -> int:
    """
    We know the keysize when we have fed 2*keysize identical
    bytes to the encryptor and the first and second keysize bytes
    of the resulting ciphertext are identical. So, start with keysize=1
    and keep going until the condition is met.
    """
    for keysize in range(1, 32): # 32 bytes = 256 bits = max key size
        bts = encryptor.encrypt(b'A' * keysize * 2)
        if bts[:keysize] == bts[keysize:keysize*2]:
            return keysize

def discover_unknown_bytes_len(encryptor: OracleEncryptor, keysize: int) -> int:
    """
    We know that the encryptor may pad whatever it encrypts so that the output is
    always a multiple of some value, n. So, we continually prepend padding of our own
    until the length of the encryptor's output increases by n. At this point, we
    know that `output_len - (n - 1) - pad_len = unknown_bytes_len`. In our case, we
    know that n = keysize.
    """
    start_len = len(encryptor.encrypt(b''))
    for pad_len in range(1, 256):
        new_len = len(encryptor.encrypt(b'A' * pad_len))
        if new_len != start_len:
            return new_len - (keysize - 1) - pad_len

def discover_unknown_bytes(encryptor: OracleEncryptor, keysize: int, known_len: int) -> bytes:
    """
    Let's say the keysize is 8 bytes. If we pass b'AAAAAAA' (len=7) as input to the encryptor, we know
    that since encryption is done in blocks of 8 bytes, the encryptor will append the first byte
    from the unknown_bytes to our input before encrypting.

    Now, let's make a list of all possible 8-byte blocks whose first seven bytes are b'AAAAAAA'.  The
    first list item is b'AAAAAAA'+b'\x00', the second b'AAAAAAA'+b'\x01', etc. Next, encrypt each of
    these 8-byte blocks, and get a list of all the ciphertexts. Then, make a dictionary where the
    keys are the ciphertexts and the values are which byte was appended to b'AAAAAAA'.

    When we encrypt our input b'AAAAAAA', we can use the corresponding block of ciphertext to lookup
    in our dictionary which byte was appended. We know that the byte that was appended was the first
    byte of the unknown_bytes.

    Let's say we found the first byte of the unknown_bytes to be b'X'. To get the second byte, we repeat
    the process described above, but this time using input b'AAAAAA' (len=7). However, we know that the
    7th byte will be b'X', so me make our dictionary using all possible ciphertexts where the first 7
    bytes of plaintext are b'AAAAAAX'.

    Let's say we find the first 8 bytes this way, and they're all b'X'. To get the 9th byte (which is
    the first byte of the next block) we do the same thing we did for the first block except that we
    care about the second block of ciphertext instead of the first. This means we pass in b'AAAAAAA'
    (len=7), and we know the encryptor will append 8 bytes we found, b'XXXXXXXX'. Therefore the first
    7 bytes of the second block will be b'XXXXXXX'. We can use that for the dictionary to find that 9th
    byte.

    This process continues until we have discovered all the bytes.
    """
    discovered_bytes = []

    for i in range(known_len):
        b_num = i  % keysize # how deep into the curent block is the byte we want
        pad   = b'A' * (keysize - b_num - 1) # encryptor input, 'pads' the unknown bytes

        bts     = pad + bytes(b for b in discovered_bytes)
        bts_blk = bts[-(keysize-1):] # all the bytes in the same block as the byte we want

        d = {encryptor.encrypt(bts_blk + bytes([b]))[:keysize] : b for b in range(256)}

        blk_num = i // keysize
        enc     = encryptor.encrypt(pad)
        enc_blk = enc[blk_num*keysize:(blk_num+1)*keysize]

        discovered_bytes.append(d[enc_blk])

    return bytes(discovered_bytes)

if __name__ == "__main__":
    main()
