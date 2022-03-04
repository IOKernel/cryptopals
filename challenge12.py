#!/usr/bin/env python3
from utils import read
from aes import detect_ecb, aes_ecb_encrypt, random_bytes_gen
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
    plaintext = pkcs7_pad(plaintext + append_text)
    ciphertext = aes_ecb_encrypt(plaintext, key)
    return ciphertext

def encrypt(plaintext: bytes, key: bytes = KEY) -> bytes:
    return ecb_encryption_oracle(plaintext, key)

def get_blocksize():
    initial_size = len(encrypt(b'A'))
    for i in range(initial_size):
        current_size = len(encrypt(b'A'*i))
        if current_size != initial_size:
            return [current_size - initial_size, initial_size]

def ecb_check():
    plaintext = b'A'*128
    ciphertext = encrypt(plaintext)
    return detect_ecb(ciphertext)

def find_character(plaintext: bytes, initial_block: bytes, secret: bytes, block: int, blocksize: int) -> bytes:
    # for 1337 effect
    #random_shiz = read('challenge12-text.txt')
    for c in printable:
        ciphertext = encrypt(plaintext + secret + c.encode())
        current_block = ciphertext[block*blocksize:block*blocksize+blocksize]
        #sct =  secret.decode().replace('\n',', ')
        #print(f"\033[32m{sct}\033[0m{c}{random_shiz[len(secret):135]}", end='\r')
        #time.sleep(0.01)
        if current_block == initial_block:
            return c.encode()

def oracle_breaking():
    blocksize, secret_size = get_blocksize()
    ecb_mode = ecb_check()
    print(f'BLOCKSIZE: {blocksize}')
    print(f'ECB MODE: {True if ecb_mode else False}')
    secret = b'' 
    for i in range(secret_size):
        block = (i // blocksize)
        plaintext = b'A'*((block+1)*blocksize-i-1)
        ciphertext = encrypt(plaintext)
        initial_block = ciphertext[block*blocksize:block*blocksize + blocksize]
        try:
            secret += find_character(plaintext, initial_block, secret, block, blocksize)
        except TypeError:
            #print(f'\N{thumbs up sign}AES-ECB Oracle Broken\N{thumbs up sign}')
            print(f'Secret: {secret.decode()}')
            break
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    oracle_breaking()

if __name__ == "__main__":
    main()