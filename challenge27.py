#!/usr/bin/env python3
from utils import get_blocks, ans_check, xor
from padding import pkcs7_pad
from aes import (
    random_bytes_gen, 
    aes_cbc_encrypt, 
    aes_cbc_decrypt
    )
#  Set 2 Challenge 16  - CBC bitflipping attacks
blocksize = 16
KEY = random_bytes_gen(blocksize)
IV = KEY
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def cbc_encryption_oracle(plaintext: bytes, key: bytes = KEY) -> bytes:
    prepend_text = b"comment1=cooking%20MCs;userdata="
    append_text = b";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = plaintext.replace(b'=', b'\\=').replace(b';', b'\\;')
    plaintext = prepend_text + plaintext + append_text
    padded = pkcs7_pad(plaintext)
    ciphertext = aes_cbc_encrypt(padded, key, IV)
    return ciphertext

def receiver_decrypt(ciphertext: bytes, key: bytes = KEY) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, key, IV)
    plain_blocks = get_blocks(plaintext)
    pt_vals = [c for c in plaintext]
    if min(pt_vals) < 32 | max(pt_vals) > 127:
        raise ValueError('Illegal characters in plaintext', plain_blocks)

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    input_text = "_admin_true"
    ciphertext = cbc_encryption_oracle(input_text.encode())
    cipher_blocks = get_blocks(ciphertext)
    # AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    # Modified msg: C_1, C_2, C_3 -> C_1, 0, C_1
    # get key: P'_1 XOR P'_3
    cipher_blocks[1] = bytes(16)
    cipher_blocks[2] = cipher_blocks[0]
    ciphertext = b''.join(cipher_blocks)
    try:
        receiver_decrypt(ciphertext)
    except ValueError as err:
        recovered_iv = xor(err.args[1][0], err.args[1][2])
    
    print(f'Recoevered IV/KEY: {recovered_iv}')
    ans_check(KEY, recovered_iv)


if __name__ == "__main__":
    main()