#!/usr/bin/env python3
from utils import get_blocks, ans_check
from aes import (
    random_bytes_gen, 
    aes_ctr_encrypt, 
    aes_ctr_decrypt
    )
#  Set 2 Challenge 16  - CBC bitflipping attacks
blocksize = 16
KEY = random_bytes_gen(blocksize)
NONCE = random_bytes_gen(blocksize//2)
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def ctr_encryption_oracle(plaintext: bytes, key: bytes = KEY) -> bytes:
    prepend_text = b"comment1=cooking%20MCs;userdata="
    append_text = b";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = plaintext.replace(b'=', b'\\=').replace(b';', b'\\;')
    plaintext = prepend_text + plaintext + append_text
    ciphertext = aes_ctr_encrypt(plaintext, key, NONCE)
    return ciphertext

def admin_check(ciphertext: bytes, key: bytes = KEY) -> bool:
    plaintext = aes_ctr_decrypt(ciphertext, key, NONCE)
    plain_blocks = get_blocks(plaintext)
    print(plain_blocks)
    if b';admin=true;' in plaintext:
        return True
    else:
        return False

def inject_text(ciphertext: bytes, cur_pt: bytes, new_text: bytes, offset: int) -> bytes:
    new_byte = bytes([ord(cur_pt)^ord(new_text)^ciphertext[offset]])
    return ciphertext[:offset] + new_byte + ciphertext[offset+1:]


# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    # get keystream byte at
    input_text = "_admin_true"
    target_text = ";admin=true"
    ciphertext = ctr_encryption_oracle(input_text.encode())
    cipher_blocks = get_blocks(ciphertext)
    # code to flip the bytes from input to wanted text
    for index, (c, w) in enumerate(zip(input_text, target_text)):
        if c != w:
            cipher_blocks[2] = inject_text(cipher_blocks[2], c, w, index)
    ciphertext = b''.join(cipher_blocks)
    ans_check(True, admin_check(ciphertext))

if __name__ == "__main__":
    main()