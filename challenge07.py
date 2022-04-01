#!/usr/bin/env python3
from base64 import b64decode
import os
from Crypto.Cipher import AES
from padding import pkcs7_unpad

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    # create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    # create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
# AES-128-ECB
def main():
    key = b"YELLOW SUBMARINE"
    # opening the file and reading the ciphertext
    dirname = os.path.dirname(__file__)
    path = os.path.join(dirname, 'challenge07-text.txt')
    with open(path) as f:
        ciphertext = b64decode(f.read())
    plaintext = aes_ecb_decrypt(ciphertext, key)
    # remove the padding after decrypting
    plaintext = pkcs7_unpad(plaintext)
    #ciphertext = aes_ecb_encrypt(plaintext.encode(), key).decode()
    print(plaintext.decode())
    
if __name__ == "__main__":
    main()
