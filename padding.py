from Crypto.Util import number
from os import urandom
def detect_padding(plaintext: bytes) -> bool:
    padding_len = plaintext[-1]
    padding = plaintext[-padding_len:]
    for i in padding:
        if i != padding_len:
            return False
    return padding_len == len(padding)

def pkcs7_pad(plaintext: bytes, blocksize=16) -> bytes:
    """ 
        Input: plaintext string or bytes, block size wanted
        Output: padded plaintext in bytes
    """
    if type(plaintext) is str:
        plaintext = plaintext.encode()
    # check for if pt is padded already or multiple of blocksize
    # WILL NOT pad if plaintext is multiple of blocksize
    if not len(plaintext)%blocksize:
        padding_state = detect_padding(plaintext)
        if padding_state:
            print('ALREADY PADDED')
            return plaintext
    rem_bytes = blocksize - len(plaintext)%blocksize
    padding = bytes([rem_bytes] * rem_bytes)        
    padded = plaintext + padding
    return padded

def pkcs7_unpad(plaintext: bytes, blocksize: int = 16) -> bytes:
    """ 
        Input: plaintext padded
        Output: unpadded plaintext
    """    
    if not len(plaintext)%blocksize:
        padding_state = detect_padding(plaintext)
        if padding_state:
            padding_len = plaintext[-1]
            return plaintext[:-padding_len]
    raise ValueError('bad padding', plaintext) 

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