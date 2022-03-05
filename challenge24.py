#!/usr/bin/env python3
from utils import Random, xor
from os import urandom
from random import randint
# --------------------------------------------------------
# ---------------------- constants -----------------------
# --------------------------------------------------------

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def bitstring_to_bytes(s):
    return s.to_bytes(4, byteorder='big')

def get_keystream(seed: int, length: int) -> list:
    rand = Random(seed)
    iterations = length//4 + (length % 4 > 0)
    keystream = b''
    for _ in range(iterations):
        rand_number = rand.random()
        byte = bitstring_to_bytes(rand_number)
        keystream += byte
    return keystream
    

def encrypt(plaintext: bytes, seed: int) -> bytes:
    length = len(plaintext)
    keystream = get_keystream(seed, length)
    return xor(plaintext, keystream)

def bruteforce_seed(keystream_known, length, seed_size = 16):
    for i in range(2**seed_size):
        seed = i
        keystream = get_keystream(seed, length)
        if keystream_known in keystream:
            print('FOUND')
            return seed

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    # setting the seed
    # first part of the encryption/decryption test
    seed = 0xDEAD
    prefix = urandom(randint(1,10))
    plaintext = b'A'*14
    ciphertext = encrypt(prefix + plaintext, seed)
    # recovering the seed
    keystream_known = xor(ciphertext[-14:], plaintext)
    recovered_seed = bruteforce_seed(keystream_known, len(plaintext+prefix))
    print(f"{recovered_seed = }\nIn hex = {hex(recovered_seed)}")
    # generate password reset token
    # check if password token is encrypted with MT19937
    # psuedo-code

if __name__ == "__main__":
    main()