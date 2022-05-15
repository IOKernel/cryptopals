#!/usr/bin/env python3
# BREAKING AES-ECB-128 oracle with randomly appended bytes in the start to extract a 
# secret from provided ciphertexts
from utils import read,  get_blocks
from aes import random_bytes_gen, aes_ecb_encrypt, detect_ecb
from padding import pkcs7_pad
from random import randint
from base64 import b64decode
from string import printable
import time

BLOCKSIZE = 16
KEY = random_bytes_gen(BLOCKSIZE)

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

def ecb_encryption_oracle(plaintext: bytes, key: bytes = KEY) -> bytes:
    append_text = b64decode(read('challenge12-text.txt'))
    plaintext = plaintext + append_text
    padded = pkcs7_pad(plaintext)
    ciphertext = aes_ecb_encrypt(padded, key)
    return ciphertext

def encrypt(plaintext: bytes, key: bytes = KEY) -> bytes:
    prepend = random_bytes_gen(randint(0,16))
    return ecb_encryption_oracle(prepend + plaintext, key)

def ecb_check() -> bool:
    plaintext = b'A'*128
    ciphertext = encrypt(plaintext)
    return detect_ecb(ciphertext)

def get_blocksize() -> tuple:
    sizes = []
    for _ in range(32):
        sizes.append(len(encrypt(b'A')))
    return max(sizes) - min(sizes), max(sizes)

def find_character(plaintext: bytes, first_block: bytes, initial_block: bytes, secret: bytes, block: int, blocksize: int) -> bytes:
    for c in printable:
        ciphertext = encrypt(plaintext + secret + c.encode())
        cipher_blocks = get_blocks(ciphertext)
        first_new_block = cipher_blocks[0]
        if first_new_block == first_block:
            if cipher_blocks[block+1] == initial_block:
                return c.encode()

def oracle_breaking():
    blocksize, secret_size = get_blocksize()
    print(f'BLOCKSIZE: {blocksize}')
    print(f'ECB MODE: {True if ecb_check() else False}')
    secret = b''
    first_block = b''
    unique_blocks = []
    while len(secret) < (secret_size-blocksize):
        block = (len(secret) // blocksize)
        plaintext = b'A'*16 + b'A'*((block+1)*blocksize-len(secret)-1)
        ciphertext = encrypt(plaintext)
        cipher_blocks = get_blocks(ciphertext)
        if cipher_blocks[0] not in unique_blocks:
            unique_blocks.append(cipher_blocks[0])
        else:
            if not first_block:
                first_block = cipher_blocks[0]
            elif first_block == cipher_blocks[0]:
                try:
                    secret += find_character(plaintext, first_block, cipher_blocks[block+1], secret, block, blocksize)
                    print(f'Secret: {secret}')
                except TypeError:
                    continue
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    oracle_breaking()

if __name__ == "__main__":
    main()