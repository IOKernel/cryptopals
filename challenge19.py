#!/usr/bin/env python3
# Break fixed-nonce CTR mode using substitutions
from base64 import b64decode, b64encode
from aes import (
    BLOCKSIZE, 
    random_bytes_gen, 
    aes_ctr_encrypt,
    aes_ctr_decrypt
    )
from utils import read, xor
from string import ascii_letters, digits
dictionary = ascii_letters + digits + " .,?!"
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def guess_keystream(ciphertexts: list, byte: bytes, pos: int) -> bool:
    for ct in ciphertexts:
        if len(ct) > pos:
            if not chr(ct[pos] ^ byte) in dictionary:
                return False
    return True

def print_pt(ciphers: list, keystream: bytes, known_length):
    for pos, cipher in enumerate(ciphers):
        print(f'{pos+1}: ', end='')
        for c_pos, c in enumerate(cipher):
            if c_pos < known_length:
                print(f'\033[32m{chr(c ^ keystream[c_pos])}\033[0m', end='')
            else:
                print(f'\033[91m{chr(c ^ keystream[c_pos])}\033[0m', end='')
        print()

def known_byte(line: int, pt: str, ciphertexts: list, keystream: bytes) -> bytes:
    if pt:
        new_bytes = xor(ciphertexts[line][len(keystream):len(keystream)+ len(pt)], pt.encode())
        return keystream + new_bytes
    return keystream
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    # given info
    plaintexts = [b64decode(pt) for pt in read('challenge19-text.txt').split()]
    key = random_bytes_gen(BLOCKSIZE)
    nonce = bytes(BLOCKSIZE//2)
    # operations
    cts = [aes_ctr_encrypt(pt, key, nonce) for pt in plaintexts]
    keystream = b''
    # Known plaintext here, concat
    keystream = known_byte(0, 'I have met them ', cts, keystream)
    keystream = known_byte(39, 'y ', cts, keystream)
    keystream = known_byte(38, 'y', cts, keystream)
    keystream = known_byte(21, 'tiful', cts, keystream)
    keystream = known_byte(14, 'erly', cts, keystream)
    keystream = known_byte(25, 'iend', cts, keystream)
    keystream = known_byte(37, ' ', cts, keystream)
    keystream = known_byte(27, ',', cts, keystream)
    keystream = known_byte(4, 'ad', cts, keystream)
    keystream = known_byte(37, 'n.', cts, keystream)

    known_length = len(keystream)
    max_pt_len = len(max(cts, key = lambda k: len(k)))
    for pos in range(len(keystream), max_pt_len):
        for byte in range(256):
            if guess_keystream(cts, byte, pos):
                keystream+=bytes([byte])
                break
    # add null bytes
    if len(keystream) < max_pt_len:
        keystream += b'0'*(max_pt_len-len(keystream))
    print_pt(cts, keystream, known_length)

if __name__ == "__main__":
    main()
