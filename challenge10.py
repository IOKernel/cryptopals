#!/usr/bin/env python3
from base64 import b64decode, b64encode
from utils import xor, read
from aes import aes_ecb_encrypt, aes_ecb_encrypt, aes_cbc_decrypt
from padding import pkcs7_pad, pkcs7_unpad
# AES default blocksize
BLOCKSIZE = 16
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------


# cbc decrypt function
# def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
#     # Check Intro to Cryptography Chapter 5 for equations
#     BLOCKSIZE = 16
#     plaintext = []
#     for block in range(0, len(ciphertext), BLOCKSIZE):
#         cipher_block = ciphertext[block:block+BLOCKSIZE]
#         if block == 0:
#             decrypted = aes_ecb_decrypt(cipher_block, key)
#             pt = xor(decrypted, iv)
#             plaintext.append(pt)
#         else:
#             decrypted = aes_ecb_decrypt(cipher_block, key)
#             ct_previous = ciphertext[block-BLOCKSIZE:block]
#             pt = xor(decrypted, ct_previous)
#             plaintext.append(pt)

#     return b''.join(plaintext)

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------

def main():
    # set IV of 16 \x00
    iv = bytes(BLOCKSIZE)
    # ciphertext from file, b64 decoded
    ciphertext = b64decode(read('challenge10-text.txt'))
    key = b"YELLOW SUBMARINE"
    pt = aes_cbc_decrypt(ciphertext, key, iv)
    plaintext_string = pkcs7_unpad(pt)
    print(plaintext_string)

if __name__ == "__main__":
    main()