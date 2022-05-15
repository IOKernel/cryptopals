#!/usr/bin/env python3
# Break an MD4 keyed MAC using length extension
from hashing import MD4
from utils import bitstring_to_bytes, ans_check
import struct
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def break_chunks(data, chunk_size: int) -> list:
        if type(data) is int:
            data = bin(data)[2:].rjust(512, '0')
        return [int(data[i:i+chunk_size],2) for i in range(0, len(data), chunk_size)]

def md_padding(keylen_guess: int, og_message: bytes):
    full_msg_len = keylen_guess + len(og_message) 
    ml = bin(full_msg_len * 8)[2:].rjust(64, '0')
    klen = 448 - ((full_msg_len*8)+1)%512
    padding = '1' + '0'*klen
    return padding, full_msg_len*8
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    # init
    key = b"manGOBAY"
    og_str = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_str = b";admin=true"
    max_keylen_guess = 12

    # get original hash and get the h vals unpacking in little endian
    og_md4 = MD4(key + og_str)
    h_vals_bytes = bytes.fromhex(og_md4.hexdigest())
    og_chunks = list(struct.unpack('<4L', h_vals_bytes))

    for i in range(1, max_keylen_guess):
        print(f"KEY LENGTH = {i}-----------------------")
        # set the h values in the generator
        og_md4.h = og_chunks

        # padding bytes for original string
        padding, ml = md_padding(i, og_str)
        padding_bytes = bitstring_to_bytes(padding)
        padding_bytes += struct.pack("<Q", ml)

        # padding bytes for forged message (key + og_str + padding + length + new_str)
        forged_padding, ml = md_padding(i, og_str + padding_bytes + new_str)
        forged_padding_bytes = bitstring_to_bytes(forged_padding)
        forged_padding_bytes += struct.pack("<Q", ml)

        # process the new blocks
        forged_message = new_str + forged_padding_bytes
        og_md4._process([forged_message[i : i + 64] for i in range(0, len(forged_message), 64)])
        forged_md4 = og_md4.hexdigest()

        # correct digest for full message
        # has to be key + og_str + padding + length + new_str
        correct_md4 = MD4(key+og_str+padding_bytes+new_str).hexdigest()
        
        print(f"{correct_md4= }")
        print(f"{forged_md4 = }")
        if ans_check(correct_md4, forged_md4):
            break

if __name__ == "__main__":
    main()