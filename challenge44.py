#!/usr/bin/env python3
# --------------------------------------------------------
# ----------------------- imports ------------------------
# --------------------------------------------------------
import re
from publickeycrypto import Dsa, modinv, DSA_recover_x_from_k
from hashing import sha1
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)
    # extract msg, r, s and md from provided file using regex
    with open('challenge44-text.txt', 'r') as f:
        text = f.read()
        msg_finder = re.compile(r'(?:msg: )(.*)')
        s_finder = re.compile(r'(?:s: )(.*)')
        r_finder = re.compile(r'(?:r: )(.*)')
        md_finder = re.compile(r'(?:m: )(.*)')
        msg_list = msg_finder.findall(text)
        s_list = s_finder.findall(text)
        r_list = r_finder.findall(text)
        md_list = md_finder.findall(text)
    
    # find accidental repeated k value
    # to find common k, we need to find a common r
    # are r is only dependent on k, with g p q being common
    for i, r in enumerate(r_list):
        if r_list.index(r) != i:
            first_dup_index = r_list.index(r)
            second_dup_index = i
            r_common = int(r)
            break
    
    # find common k
    # k = (md1 - md2) * modinv(s1 - s2, q) % q
    md1 = int(md_list[first_dup_index], 16)
    md2 = int(md_list[second_dup_index], 16)
    s1 = int(s_list[first_dup_index])
    s2 = int(s_list[second_dup_index])
    k = (md1 - md2) * modinv(s1 - s2, Dsa().q) % Dsa().q
    print(f"k: {k}")

    # calculate private key x from k, r, s, md
    x = DSA_recover_x_from_k(k, r_common, s1, md1)
    x_hash = sha1(hex(x)[2:]).hexdigest()
    print(f"x (sha1): {x_hash}")
    # check if found private key matches the one in the challenge
    priv_key_hash = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    if x_hash == priv_key_hash:
        print("Private key matches!")
    else:
        print("Private key does not match!")

if __name__ == "__main__":
    main()