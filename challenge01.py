#!/usr/bin/env python3
# Convert hex to base64 
import string
from base64 import b64encode
from utils import ans_check
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def hexToB64(data: str) -> bytes:
    '''
    a function that takes input hex and returns base64 encoded
    bytes
    '''
    # check if all input is hex data
    if not all(c in string.hexdigits for c in data):
        raise ValueError("input is not hexstring")
    unhexed = bytes.fromhex(data)
    #decode: b"I'm killing your brain like a poisonous mushroom"
    output = b64encode(unhexed)
    return output

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
def main():
    hexed = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

    answer = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    result = hexToB64(hexed)
    ans_check(result, answer)

if __name__ == '__main__':
    main()