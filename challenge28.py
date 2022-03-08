#!/usr/bin/env python3

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def str_to_binary(msg):
    # converts the string to binary and output a base10 integer
    return int(''.join([format(ord(c), 'b') for c in msg]),2)

def sha1(message: str) -> bytes:
    def _break_chunks(data: int, chunk_size: int) -> list:
        data = bin(data)[2:]
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    # initializing constants:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    ml = len(message) * 8
    
    ## pre-processing:
    bin_msg = str_to_binary(message)
    # append 1
    bin_msg = bin_msg << 1 | 1
    bin_len = len(bin(bin_msg)[2:])
    # make len of bin_msg = 448 (mod 512) by appending 0s
    if bin_len % 512 > 448:
        bin_msg = bin_msg << (512-(bin_len%512 - 448))
    else:
        bin_msg = bin_msg << (448 - (len(bin(bin_msg)[2:])%512))
    # append ml as 64 bit big-endian
    bin_msg = int(bin(bin_msg)[2:] + bin(ml)[2:].rjust(64, '0'), 2)
    ## process message in 512-bit chunks
    chunks_512 = _break_chunks(bin_msg, 512)
    for chunk in chunks_512:
        print(len(chunk))

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    sha1('a'*100)

if __name__ == "__main__":
    main()