#!/usr/bin/env python3
from utils import (
    read, 
    get_blocks,
    ans_check
    )
from padding import pkcs7_pad, pkcs7_unpad
from aes import (
    random_bytes_gen, 
    aes_cbc_encrypt, 
    aes_cbc_decrypt,
    detect_padding
    )
from base64 import b64decode
from random import randint
from string import printable
BLOCKSIZE = 16
KEY = random_bytes_gen(BLOCKSIZE)
IV = random_bytes_gen(BLOCKSIZE)
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def random_encrypt(plaintexts: list) -> bytes:
    rand_int = randint(0, 9)
    plaintext = plaintexts[rand_int].encode()
    ct = aes_cbc_encrypt(pkcs7_pad(plaintext), KEY, IV)
    return (ct, IV)

def validate_padding(ciphertext: bytes, iv: bytes) -> bool:
    pt = aes_cbc_decrypt(ciphertext, KEY, iv)
    return detect_padding(pt)

def bit_flip(previous_block: bytes, guess: int, flip_pos: int, padding_size: int) -> bytes:
    flipped_byte = bytes([previous_block[flip_pos] ^ guess ^ padding_size])
    return previous_block[:flip_pos] + flipped_byte + previous_block[flip_pos+1:]

def reconstruct_block(previous_block: bytes, byte: int, c: str, padding_size: int, recovered_pt: list) -> bytes:
    for index, pt in enumerate(reversed(recovered_pt)):
        previous_block = bit_flip(previous_block, pt, BLOCKSIZE - index -1, padding_size)        
    return bit_flip(previous_block, c, BLOCKSIZE - padding_size, padding_size) # byte 14, 15

def get_pt(previous_block: bytes, current_block: bytes, recovered_pt: list, byte: int) -> bytes:
    padding_size = len(recovered_pt) + 1
    for c in range(256):
        reconstructed_block = reconstruct_block(previous_block, byte, c, padding_size, recovered_pt)
        if validate_padding(current_block, reconstructed_block):
            return c
    raise Exception('No solution found')

def get_cbc_padding_size(previous_block: bytes, current_block: bytes) -> int:
    """
        Reconstruct prev block, flipping all bytes starting with first byte
        until validate padding is no longer true
    """
    for byte in range(16):
        previous_block = bit_flip(previous_block, 255, byte, 0)
        if not validate_padding(current_block, previous_block):
            return 16 - byte

def cbc_padding_oracle_atk(ct: bytes, iv: bytes):
    ct_blocks = get_blocks(ct)
    recovered_pt = []
    padding_size_last = get_cbc_padding_size(ct_blocks[-2], ct_blocks[-1])
    for block_index, ct_block in enumerate(ct_blocks):
        for byte in reversed(range(BLOCKSIZE)):
            # first block
            if not block_index: 
                previous_block = iv
                pt = get_pt(previous_block, ct_block, recovered_pt[block_index*BLOCKSIZE:(block_index+1)*BLOCKSIZE], byte)
                recovered_pt.insert(0, pt)
                continue
            # Final block
            elif block_index == (len(ct_blocks) - 1): 
                previous_block = ct_blocks[block_index-1]
                if 15 - byte < padding_size_last:
                    pt = padding_size_last
                    recovered_pt.insert(0, pt)
                    continue
            # all other blocks
            previous_block = ct_blocks[block_index-1]
            pt = get_pt(previous_block, ct_block, recovered_pt[:-block_index*BLOCKSIZE], byte)
            if pt is not None:
                recovered_pt.insert(0, pt)

    plaintext = []
    for index, pt in enumerate(reversed(recovered_pt)):
        plaintext.insert((index//BLOCKSIZE)*BLOCKSIZE, pt)
    return b''.join(chr(c).encode() for c in plaintext)
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    plaintexts = read('challenge17-text.txt').split()
    for index, plaintext in enumerate(plaintexts):
        print(f'decryption of plaintext #{index+1}: ', end='')
        ct = aes_cbc_encrypt(pkcs7_pad(plaintext.encode()), KEY, IV)
        decryption = cbc_padding_oracle_atk(ct, IV)
        decryption = pkcs7_unpad(decryption)
        ans_check(plaintext.encode(), decryption)
        print(b64decode(decryption))

if __name__ == "__main__":
    main()