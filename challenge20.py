 #!/usr/bin/env python3
 # Break fixed-nonce CTR statistically
from base64 import b64decode, b64encode
from aes import (
    BLOCKSIZE, 
    random_bytes_gen, 
    aes_ctr_encrypt,
    aes_ctr_decrypt
    )
from utils import read, xor
from string import ascii_letters, digits
dictionary = ascii_letters.encode() + digits.encode() +  b':;., /?'
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def extract(lists: list, index: int) -> list:
    return [item[index] for item in lists]

def get_score(message: bytes) -> int:
    return sum([c in dictionary for c in message])
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    # Note: it sometimes takes the wrong first byte, lowercase letters instead 
    # of upper case. Resulting in an error only in the ' character. 
    # given info
    plaintexts = [b64decode(pt) for pt in read('challenge20-text.txt').split()]
    key = random_bytes_gen(BLOCKSIZE)
    nonce = bytes(BLOCKSIZE//2)
    # operations
    cts = [aes_ctr_encrypt(pt, key, nonce) for pt in plaintexts]
    min_pt_len = len(min(cts, key = lambda k: len(k)))
    # cut the strings to min length
    keystream = b''
    cts_truncated = [ct[:min_pt_len] for ct in cts]
    for i in range(min_pt_len):
        index_bytes = extract(cts_truncated, i)
        max_score = 0
        for byte in range(256):
            xored = xor(index_bytes, bytes([byte]))
            score = get_score(xored)
            if score > max_score:
                max_score = score
                guessed_byte = bytes([byte])
        keystream += guessed_byte
    for ct in cts_truncated:
        print(xor(ct,keystream))
        
if __name__ == "__main__":
    main()
