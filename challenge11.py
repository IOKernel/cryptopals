#!/usr/bin/env python3
from random import randint
from os import urandom
from utils import read
from padding import pkcs7_pad
from aes import (
    aes_ecb_encrypt, 
    aes_cbc_encrypt, 
    detect_ecb,
    aes_cbc_decrypt
)
BLOCKSIZE = 16

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

def random_key_gen(length: int) -> bytes:
    # need urandom from os
    return urandom(length)

def append_bytes(plaintext: bytes) -> bytes:
    # needs randint from random
    start = random_key_gen(randint(5, 10))
    end = random_key_gen(randint(5, 10))
    output_tuple = (start, plaintext, end)
    return b''.join(output_tuple)

def encryption_oracle(plaintext: str) -> bytes:
    # needs randint from random
    # from utils import aes_ecb_encrypt, aes_cbc_encrypt, detect_ecb
    key = random_key_gen(BLOCKSIZE)
    iv = random_key_gen(BLOCKSIZE)
    print(f'\033[34mkey\033[0m = {key}')
    print(f'\033[34miv\033[0m = {iv}')
    if type(plaintext) is str:
        plaintext = plaintext.encode()
    appended_pt = append_bytes(plaintext)
    padded_pt = pkcs7_pad(appended_pt) 
    # random value: 0 | 1
    rand_int = randint(0,1)
    if rand_int:
        print("\033[34mMODE\033[0m: ECB MODE")
        ciphertext = aes_ecb_encrypt(padded_pt, key)
    else:
        print("\033[34mMODE\033[0m: CBC MODE")
        ciphertext = aes_cbc_encrypt(padded_pt, key, iv)
    return ciphertext, key, iv

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    # adding some colors for better readibility
    print('\033[96m=\033[0m'*128)
    pt = 'A'*128
    ciphertext, _, _ = encryption_oracle(pt)
    print(f'\033[34mciphertext\033[0m: {ciphertext}')
    print(f'\033[34mECB MODE\033[0m? {detect_ecb(ciphertext)}')
    print('\033[96m=\033[0m'*128)

if __name__ == "__main__":
    main()