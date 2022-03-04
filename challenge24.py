#!/usr/bin/env python3
from utils import Random, xor

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
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    seed = 0xDEAD
    ciphertext = encrypt(b'hello world!', seed)
    print(ciphertext)
if __name__ == "__main__":
    main()