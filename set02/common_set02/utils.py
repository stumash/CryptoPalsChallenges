from math import ceil

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

#-------------------------------
# PKCS7 PADDING
#-------------------------------

def pkcs7(bts: bytes, blk_size: int):
    """
    Right-pad with up to 255 bytes. The padding byte
    used is equal to the number of bytes padded.
    """
    if not blk_size <= 256:
        raise ValueError('assert(blk_size < 256)')

    pad = abs(len(bts) - ceil(len(bts) / blk_size) * blk_size)
    return bytes(pad if not i < len(bts) else bts[i] for i in range(len(bts)+pad))

#-------------------------------
# ECB-MODE AES
#-------------------------------

def aes_ecb_encrypt(bts: bytes, key: bytes) -> bytes:
    if len(bts) % len(key) != 0:
        raise ValueError('assert(len(bts)%len(key)==0)')

    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    return encryptor.update(bts)

def aes_ecb_decrypt(bts: bytes, key: bytes) -> bytes:
    if len(bts) % len(key):
        raise ValueError('assert(len(bts)%len(key)==0)')

    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    return decryptor.update(bts)

#-------------------------------
# CBC-MODE AES
#-------------------------------

def aes_cbc_encrypt(bts: bytes, key: bytes, iv: bytes) -> bytes:
    if len(bts) % len(iv) != 0 or len(iv) != len(key):
        raise ValueError('assert(len(iv)==len(key) and len(bts)%len(key)==0)')

    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    dec_blks = [bts[i:i+len(iv)] for i in range(0,len(bts),len(iv))]

    enc_blks = [iv]
    for blk in dec_blks:
        prev = enc_blks[-1]
        enc_blks.append( encryptor.update(xor(blk,prev)) )

    return b''.join(enc_blks[1:])

def aes_cbc_decrypt(bts: bytes, key: bytes, iv: bytes) -> bytes:
    if len(bts) % len(iv) != 0 or len(iv) != len(key):
        raise ValueError('assert(len(iv)==len(key) and len(bts)%len(key)==0)')

    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    enc_blks = [iv] + [bts[i:i+len(iv)] for i in range(0,len(bts),len(iv))]

    dec_blks = [xor(enc_blks[i-1], decryptor.update(enc_blks[i])) for i in range(1,len(enc_blks))]

    return b''.join(dec_blks)

def xor(bts1: bytes, bts2: bytes):
    if len(bts1) != len(bts2):
        raise ValueError('assert(len(bts1) == len(bts2))')

    return bytes(b1^b2 for b1,b2 in zip(bts1,bts2))

#-------------------------------
# ECB/CBC DETECTION ORACLE
#-------------------------------

def ecb_cbc_detection_oracle(bts: bytes, keylen: int) -> str:
    if len(bts) % keylen != 0:
        raise ValueError('assert(len(bts) % keylen == 0)')

    blks = [bts[i:i+keylen] for i in range(0,len(bts),keylen)]

    if len(blks) != len(set(blks)): return 'ecb'
    else: return 'cbc'
