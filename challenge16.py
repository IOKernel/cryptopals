#!/usr/bin/env python3
# CBC bitflipping attacks
from utils import get_blocks, ans_check
from padding import pkcs7_pad
from aes import (
    random_bytes_gen, 
    aes_cbc_encrypt, 
    aes_cbc_decrypt
    )
#  Set 2 Challenge 16  - CBC bitflipping attacks
blocksize = 16
KEY = random_bytes_gen(blocksize)
IV = random_bytes_gen(blocksize)
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

def admin_check(ciphertext: bytes, key: bytes = KEY) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, key, IV)
    plain_blocks = get_blocks(plaintext)
    print(plain_blocks)
    if b';admin=true;' in plaintext:
        return True
    else:
        return False

def bit_flip(previous_block: bytes, input_text: bytes, target: bytes) -> bytes:
    '''
        input a block of 16 bytes previous to the block of inputted text 
        to be manipulated to produce target_text when decrypted, use '_'
        in spots where you want the bits to flip
    '''
    if len(input_text) != len(target):
        raise ValueError("mismatched input and target sizes")
    flipped_bytes = b''
    for index, c in enumerate(input_text):
        if chr(c) == '_':
            flipping_key = ord('_') ^ target[index]
            flipped_byte = bytes([previous_block[index] ^ flipping_key])
            flipped_bytes += flipped_byte
        else:
            flipped_bytes += bytes([previous_block[index]])
    if len(input_text) < len(previous_block):
        flipped_bytes += previous_block[len(input_text):]
    return flipped_bytes

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    input_text = "_admin_true"
    target_text = ";admin=true"
    ciphertext = cbc_encryption_oracle(input_text.encode())
    cipher_blocks = get_blocks(ciphertext)
    cipher_blocks[1] = bit_flip(cipher_blocks[1], input_text.encode(), target_text.encode())
    ciphertext = b''.join(cipher_blocks)
    ans_check(True, admin_check(ciphertext))

if __name__ == "__main__":
    main()