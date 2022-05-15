#!/usr/bin/env python3
# Implement CTR, the stream cipher mode
from base64 import b64decode, b64encode
from aes import BLOCKSIZE, aes_ecb_encrypt
from padding import pkcs7_pad
from utils import xor, get_blocks, ans_check
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def bytes_counter(counter: int = 0, blocksize: int = 16) -> bytes:
    counter = hex(counter)[2:]
    if len(counter)%2:
        counter = '0' + counter
    counter_bytes = bytes.fromhex(counter)
    return counter_bytes + bytes(blocksize//2-len(counter_bytes))

def get_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    keystream = []
    for i in range(length):
        counter_bytes = nonce + bytes_counter(i)
        ks = aes_ecb_encrypt(counter_bytes, key)
        keystream.append(ks)
    return keystream

def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    pt_blocks = get_blocks(plaintext)
    keystream_length = len(pt_blocks)
    keystream = get_keystream(key, nonce, keystream_length)
    ciphertext = []
    for block, cipher_block in enumerate(pt_blocks):
        ct = xor(cipher_block, keystream[block])
        ciphertext.append(ct)
    return b''.join(ciphertext)

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher_blocks = get_blocks(ciphertext)
    keystream_length = len(cipher_blocks)
    keystream = get_keystream(key, nonce, keystream_length)
    plaintext = []
    for block, cipher_block in enumerate(cipher_blocks):
        pt = xor(cipher_block, keystream[block])
        plaintext.append(pt)
    return b''.join(plaintext)

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    # format=64 bit unsigned little endian nonce,
    # 64 bit little endian block count (byte count / 16)
    ct_given = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    key = b'YELLOW SUBMARINE'
    nonce = bytes(BLOCKSIZE//2)
    plaintext = aes_ctr_decrypt(ct_given, key, nonce)
    print(plaintext)
    ciphertext = aes_ctr_encrypt(plaintext, key, nonce)
    ans_check(ciphertext, ct_given)

if __name__ == "__main__":
    main()