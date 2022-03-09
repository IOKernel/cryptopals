#!/usr/bin/env python3

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def str_to_binary(msg):
    # converts the string to binary and output a base10 integer
    return int(''.join([format(ord(c), 'b') for c in msg]),2)

def sha1(message: str) -> bytes:
    def _break_chunks(data: int, chunk_size: int) -> list:
        if type(data) is int:
            data = bin(data)[2:].rjust(512, '0')
        return [int(data[i:i+chunk_size],2) for i in range(0, len(data), chunk_size)]

    def _left_rotate(data: int, rot_val: int):
        # rotates bit vals
        return ((data << rot_val)|(data >> (32 - rot_val))) % wrap_32

    # initializing constants:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    ml = bin(len(message) * 8)[2:].rjust(64, '0')
    wrap_32 = 2**32
    
    ## pre-processing:
    if message:
        bin_msg = str_to_binary(message)
    else:
        bin_msg = 0
    # append 1
    klen = 448 - ((len(message)*8)-1)%512
    bin_msg = bin_msg << 1 | 1
    bin_len = len(bin(bin_msg)[2:])
    # make len of bin_msg = 448 (mod 512) by appending 0s
    # if bin_len % 512 > 448:
    #     bin_msg = bin_msg << (512-(bin_len%512 - 448))
    # else:
    #     bin_msg = bin_msg << (448 - (len(bin(bin_msg)[2:])%512))
    # append ml as 64 bit big-endian
    bin_msg = bin(bin_msg)[2:] + ('0'*klen) + ml
    ## process message in 512-bit chunks
    chunks_512 = _break_chunks(bin_msg, 512)
    for chunk in chunks_512:
        w = [0]*80
        w[0:16] = _break_chunks(chunk, 32)
        for i in range(16,80):
            w[i] = _left_rotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)
        print(w)
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
    return hex(hh)
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    digest = sha1('The quick brown fox jumps over the lazy dog')
    print(digest[2:])
    print('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')
if __name__ == "__main__":
    main()