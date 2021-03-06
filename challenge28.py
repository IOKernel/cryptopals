#!/usr/bin/env python3
# Implement a SHA-1 keyed MAC
from utils import ans_check
import hashing
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def sha1(message: str) -> bytes:
    def _break_chunks(data: int, chunk_size: int) -> list:
        if type(data) is int:
            data = bin(data)[2:].rjust(512, '0')
        return [int(data[i:i+chunk_size],2) for i in range(0, len(data), chunk_size)]

    def _left_rotate(data: int, rot_val: int):
        # rotates bit vals
        return ((data << rot_val)|(data >> (32 - rot_val))) % wrap_32
    def _str_to_binary(msg):
        # converts the string to binary and output a base10 integer
        return ''.join([format(ord(c), 'b').rjust(8,'0') for c in msg])
    # initializing constants:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    ml = bin(len(message) * 8)[2:].rjust(64, '0')
    wrap_32 = 2**32
    ## pre-processing:
    bin_msg = _str_to_binary(message)
    # append 1
    klen = 448 - ((len(message)*8)+1)%512
    bin_msg = bin_msg + '1' + '0'*klen + ml
    ## process message in 512-bit chunks
    chunks_512 = _break_chunks(bin_msg, 512)
    for chunk in chunks_512:
        w = [0]*80
        w[0:16] = _break_chunks(chunk, 32)
        for i in range(16,80):
            w[i] = _left_rotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1) % wrap_32
        # Initialize hash value for this chunk: 
        a = h0 
        b = h1 
        c = h2 
        d = h3 
        e = h4 
        # main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (_left_rotate(a,5) + f + e + k + w[i]) % wrap_32
            e = d 
            d = c 
            c = _left_rotate(b, 30) % wrap_32
            b = a 
            a = temp 
        h0 = (h0 + a) % wrap_32
        h1 = (h1 + b) % wrap_32
        h2 = (h2 + c) % wrap_32
        h3 = (h3 + d) % wrap_32
        h4 = (h4 + e) % wrap_32
    # Produce the final hash value (big-endian) as a 160-bit number:
    hh = h0<<128 | h1<<96 | h2<<64 | h3<<32 | h4
    return hex(hh)[2:]
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    ans_check(hashing.sha1(b'The quick brown fox jumps over the lazy dog').hexdigest(), '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')
    ans_check(hashing.sha1(b'The quick brown fox jumps over the lazy cog').hexdigest(), 'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3')
    ans_check(hashing.sha1(b'').hexdigest(), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
    key = b'ahdasjhd'
    print(hashing.sha1(key+b'hello').hexdigest())
    print(hashing.sha1(b'ahdasjhc'+b'hello').hexdigest())

if __name__ == "__main__":
    main()