from Crypto.Util import number
from os import urandom
def detect_padding(plaintext: bytes) -> bool:
    padding_len = plaintext[-1]
    padding = plaintext[-padding_len:]
    for i in padding:
        if i != padding_len:
            return False
    return True

def pkcs7_pad(plaintext: bytes, blocksize=16) -> bytes:
    if type(plaintext) is str:
        plaintext = plaintext.encode()

    padding_len = blocksize - (len(plaintext) % blocksize)
    if padding_len == 0:
        padding_len = blocksize

    padding = bytes([padding_len] * padding_len)
    padded = plaintext + padding
    return padded

def pkcs7_unpad(padded: bytes) -> bytes:
    padding_len = padded[-1]
    if padding_len <= 0 or padding_len > len(padded):
        raise ValueError("Invalid padding length")

    padding = padded[-padding_len:]
    if all(byte == padding_len for byte in padding):
        return padded[:-padding_len]
    else:
        raise ValueError("Invalid padding bytes")

def PKCS1_v1_5_pad(m, n, MODE = 1):
    # pad the message with PKCS1_v1_5 padding
    # returns (padded_m)
    # pad_length is the number of bytes added to the message

    # modbits/k Taken from pycryptodome implementation
    modBits = number.size(n)
    k = number.ceil_div(modBits,8)

    pad_length = k - len(m) - 3
    if MODE == 1:
        padded_m = b"\x00\x01" + b"\xff" * pad_length + b"\x00" + m
    elif MODE == 2:
        padded_m = b"\x00\x02" + urandom(pad_length) + b"\x00" + m
    return padded_m