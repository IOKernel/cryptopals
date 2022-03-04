#!/usr/bin/env python3
import os
from utils import read
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    """ 
        Input: Ciphertext bytes or hexed string
        Output: True if ciphertext has a repeating block
                False if ciphertext has no repeating block
    """

    blocks = []
    blocks_count = len(ciphertext)//block_size
    for i in range(blocks_count):
        # split ciphertext in blocks of block_size. 16 for AES
        current_block = ciphertext[i*block_size:(i+1)*block_size]
        if current_block in blocks:
            return True
        else:
            blocks.append(current_block)
    return False

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
# AES-128-ECB
def main():
    # opening the file and reading the ciphertext
    ciphertexts = read('challenge8-text.txt')
    for count, ciphertext in enumerate(ciphertexts.split()):
        #! each ciphertext is 10 blocks of 16 bytess
        ciphertext = bytes.fromhex(ciphertext)
        if detect_ecb(ciphertext):
            print("ECB DETECTED at cipher #", count+1)
            print("CIPHERTEXT: ", ciphertext)

if __name__ == "__main__":
    main()