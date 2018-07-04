import math

def pkcs7(bts, blk_size: int):
    """
    bts: bytes to right pad
    blk_size: int < 256

    Right-pad bts until blk_size divides len(bts).
    The byte value to pad with is the number bytes padded.

    returns: the padded bts
    """
    if not blk_size < 256:
        raise ValueError('need blk_size < 256')

    pad = abs(len(bts) - math.ceil(len(bts) / blk_size) * blk_size)
    return bytes(pad if not i < len(bts) else bts[i] for i in range(len(bts)+pad))
