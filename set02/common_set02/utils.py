from math import ceil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pkcs7(bts: bytes, blk_size: int):
    """
    Right-pad with up to 255 bytes. The padding byte
    used is equal to the number of bytes padded.
    """
    if not blk_size <= 256:
        raise ValueError('assert(blk_size < 256)')

    pad = abs(len(bts) - ceil(len(bts) / blk_size) * blk_size)
    return bytes(pad if not i < len(bts) else bts[i] for i in range(len(bts)+pad))

def aes_cbc_encrypt(bts: bytes, key: bytes, iv: bytes):
    if len(bts) % len(iv) != 0 or len(iv) != len(key):
        raise ValueError('assert(len(iv)==len(key) and len(bts)%len(key)==0)')

    backend   = default_backend()
    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    print(len(bts), len(iv), len(bts)//len(iv))
    blks = [bts[i*len(iv):(i+1)*len(iv)] for i in range(len(bts)//len(iv))]
    print(len(blks), blks)

    enc_blks = [iv]
    for i in range(1,len(blks)):
        print(i, len(blks))
        e = enc_blks[i-1]
        b = blks[i]
        enc_blks.append( encryptor.update(xor(e, b)) )

    return b''.join(enc_blks[1:])

def aes_cbc_decrypt(bts: bytes, key: bytes, iv: bytes):
    if len(bts) % len(iv) != 0 or len(iv) != len(key):
        raise ValueError('assert(len(iv)==len(key) and len(bts)%len(key)==0)')

    backend   = default_backend()
    cipher    = Cipher(algorithms.AES(key), modes.ECB(), backend = backend)
    decryptor = cipher.decryptor()
    
    blks     = [iv] + [bts[i*len(iv):(i+1)*len(iv)] for i in range(len(bts)//len(iv))]
    print(len(blks))
    dec_blks = [xor(blks[i-1],decryptor.update(blks[i])) for i in reversed(range(len(blks)))]

    return b''.join(dec_blks)

def xor(bts1: bytes, bts2: bytes):
    if len(bts1) != len(bts2):
        raise ValueError('assert(len(bts1) == len(bts2))')

    return bytes(b1^b2 for b1,b2 in zip(bts1,bts2))
