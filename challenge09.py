#!/usr/bin/env python3
# Implement PKCS#7 padding
from utils import ans_check
from padding import pkcs7_pad, pkcs7_unpad
BLOCKSIZE = 16
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
# def pkcs7_pad(plaintext: bytes, bs=16) -> bytes:
#     """
#         Input: plaintext string or bytes, block size wanted
#         Output: padded plaintext in bytes   
#     """

#     if type(plaintext) is str:
#         plaintext = plaintext.encode()
#     rem_bytes = bs - len(plaintext)%bs
#     padding = bytes([rem_bytes] * rem_bytes)
#     return plaintext + padding

# def pkcs7_unpad(plaintext: bytes) -> bytes:
#     """ 
#         Input: plaintext padded
#         Output: unpadded plaintext
#     """    
    
#     padding_len = plaintext[-1]
#     return plaintext[:-padding_len]

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
# AES-128-ECB
def main():
    plaintext = "YELLOW SUBMARINE"
    answer = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    padded = pkcs7_pad(plaintext, 20)
    ans_check(answer, padded)
    print(padded)
    print(pkcs7_unpad(padded, 20))

if __name__ == "__main__":
    main()