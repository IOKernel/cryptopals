#!/usr/bin/env python3
from utils import read
from aes import (
    random_bytes_gen,
    aes_ctr_encrypt,
    aes_ctr_decrypt
)
from string import printable

KEY = random_bytes_gen(16)
NONCE = random_bytes_gen(8)

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def edit_ctr(ciphertext: bytes, offset: int, newtext: bytes, key: bytes = KEY, nonce: bytes = NONCE) -> bytes:
    plaintext = aes_ctr_decrypt(ciphertext, key, nonce)
    plaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    return aes_ctr_encrypt(plaintext, key, nonce)

def recover_ctr_plaintext(ciphertext: bytes) -> bytes:
    plaintext = b""
    for index in range(len(ciphertext)):
        for c in printable.encode():
            # makes the code much faster to not send entire ct to edit
            cipher_chunk = ciphertext[:index+1]
            new_cipher = edit_ctr(cipher_chunk, index, bytes([c]))
            if new_cipher[index] == cipher_chunk[index]:
                plaintext += bytes([c])
                print(plaintext)
    return plaintext
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    plaintext = read('challenge25-text.txt').encode()
    ciphertext = aes_ctr_encrypt(plaintext, KEY, NONCE)
    recovered_pt = recover_ctr_plaintext(ciphertext)
    print(recovered_pt)
    
if __name__ == "__main__":
    main()

