#!/usr/bin/env python3
from Crypto.Cipher import AES
from os import urandom
import os
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
BLOCKSIZE = 16
def xor(a: bytes, b: bytes) -> bytes:
    '''
        to get the key to roll over, the module operator
        is used over the length of the key, 
        so string_pos MOD key_length
        ex: 0%3 = 0, 1%3 = 1, 2%3 = 2, 3%3 = 0, etc..
    '''
    xored = []
    for char_pos, c in enumerate(a):
        xored.append(c ^ b[char_pos%len(b)])
    return bytes(xored)


def ans_check(answer, result) -> str:
    # compare if results match
    if (result == answer):
        print('\033[32m'+"Passed\033[0m")
    else:
        print('\033[91m'+"FAILED\033[0m")

def read(filename: str) -> str:
    '''opening the file and reading the ciphertext'''
    dirname = os.path.dirname(__file__)
    path = os.path.join(dirname, filename)
    with open(path) as f:
        content = f.read()
    return content


def get_blocks(data: bytes, bs: int = 16) -> list:
    return [data[i:i+bs] for i in range(0, len(data), bs)]

def block_bit_flip(block: bytes, guess: int, flip_pos: int, new_byte: int) -> bytes:
    flipped_byte = bytes([block[flip_pos] ^ guess ^ new_byte])
    return block[:flip_pos] + flipped_byte + block[flip_pos+1:]

