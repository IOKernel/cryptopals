#!/usr/bin/env python3
from hashing import sha1
from utils import ans_check
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def md_padding(keylen_guess: int, og_message: bytes):
    full_msg_len = keylen_guess + len(og_message) 
    ml = bin(full_msg_len * 8)[2:].rjust(64, '0')
    klen = 448 - ((full_msg_len*8)+1)%512
    padding = '1' + '0'*klen + ml
    return padding

def break_chunks(data, chunk_size: int) -> list:
        if type(data) is int:
            data = bin(data)[2:].rjust(512, '0')
        return [int(data[i:i+chunk_size],2) for i in range(0, len(data), chunk_size)]

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    # init
    key = b"MangoBay"
    og_str = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_str = b";admin=true"
    max_keylen_guess = 12

    # get original hash with MAC
    print('Original sha----------------')
    og_sha = bin(int(sha1(key+og_str).hexdigest(), 16))[2:].rjust(160,'0')
    og_chunks = break_chunks(og_sha, 32)

    for i in range(1, max_keylen_guess):
        print(f"KEY LENGTH = {i}-----------------------")
        # get og_padding + len in bytes format
        padding = md_padding(i, og_str)
        padding_bytes = bitstring_to_bytes(padding)
        
        # correct sha if we use original key
        # has to be key + og_str + padding + length + new_str
        forged_padding = md_padding(i, og_str+padding_bytes+new_str)
        new_sha = sha1(new_str, og_chunks, padding=forged_padding).hexdigest()
        correct_sha = sha1(key+og_str+padding_bytes+new_str).hexdigest()

        print(f"{correct_sha= }")
        print(f"{new_sha=     }")

        if ans_check(new_sha, correct_sha):
            break
        
if __name__ == "__main__":
    main()