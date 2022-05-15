#!/usr/bin/env python3
# Create the MT19937 stream cipher and break it
from utils import Random, xor, ans_check
from os import urandom
from random import randint
import time
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

def gen_reset_token() -> int:
    seed = int(time.time())
    rand = Random(seed)
    return rand.random()

def mt19937_time_seeded(rand_number: int) -> bool:
    cur_time = int(time.time())
    for i in range(10000):
        seed = cur_time - i
        rand = Random(seed)
        if rand_number == rand.random():
            return True
    return False
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    # setting the seed
    # Part 1: encryption/decryption test
    seed = 0xDEAD
    plaintext = b"Hello world!"
    ciphertext = encrypt(plaintext, seed)
    plaintext_decrypt = encrypt(ciphertext, seed)
    print('Encrypt/Decrypt: ', end='')
    ans_check(plaintext, plaintext_decrypt)

    # Part 2: recovering the seed
    prefix = urandom(randint(1,10))
    plaintext = b'A'*14
    ciphertext = encrypt(prefix + plaintext, seed)
    keystream_known = xor(ciphertext[-14:], plaintext)
    recovered_seed = bruteforce_seed(keystream_known, len(plaintext+prefix))
    print('Seed recovery: ', end='')
    ans_check(seed, recovered_seed)
    print(f"{recovered_seed = }\nIn hex = {hex(recovered_seed)}")

    # Part 3: generate password reset token
    token = gen_reset_token()
    time_seeded = mt19937_time_seeded(token)
    print('Token time seeded: ', end='')
    ans_check(True, time_seeded)
    print(f'{token = }')
    # check if password token is encrypted with MT19937
    print(f'Token seeded with time? {time_seeded}')

if __name__ == "__main__":
    main()