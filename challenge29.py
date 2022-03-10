#!/usr/bin/env python3
from hashing import sha1
from utils import ans_check
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def md_padding(keylen_guess: int, og_message: str, new_message: str):
    padding = bin((keylen_guess + len(og_message) + len(new_message)) * 8)[2:].rjust(64, '0')
    return padding

def break_chunks(data, chunk_size: int) -> list:
        if type(data) is int:
            data = bin(data)[2:].rjust(512, '0')
        return [int(data[i:i+chunk_size],2) for i in range(0, len(data), chunk_size)]

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    key = "mango"
    og_str = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_str = ";admin=true"
    max_keylen_guess = 8
    og_sha = bin(int(sha1(key+og_str), 16))[2:]
    og_chunks = break_chunks(og_sha, 32)
    print(og_chunks)
    # correct sha if we use original key
    correct_sha = sha1(key+og_str+new_str)
    for i in range(1, max_keylen_guess):
        print(f"KEY LENGTH = {i}-----------------------")
        padding = md_padding(i, og_str, new_str)
        print(padding)
        new_sha = sha1(new_str, og_chunks, padding)
        ans_check(new_sha, correct_sha)
if __name__ == "__main__":
    main()