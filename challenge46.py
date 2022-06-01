#!/usr/bin/env python3
# RSA parity oracle
# --------------------------------------------------------
# ----------------------- imports ------------------------
# --------------------------------------------------------
from publickeycrypto import Rsa, int2bytes
from base64 import b64decode
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def oracle(rsa: Rsa, ct: bytes) -> bool:
    """
    input: rsa = Rsa object
           ct = ciphertext
    output: parity of ct, True if even, False if odd
    """
    pt = rsa.decrypt(ct)
    return pt % 2 == 0

def break_rsa(rsa: Rsa, ct: int) -> bytes:
    """
    input: rsa = Rsa object
           ct = ciphertext
    output: plaintext
    """
    # if c1 * c2 = ct, then pt = p1 * p2. In this case p2  = 2 * i
    e, n = rsa.getPubKey()
    lower_bound, upper_bound = 0, n

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    rsa = Rsa(512) # 1024-bit modulus size
    pt = b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    ct, _ = rsa.encrypt(pt)
    break_rsa(rsa, ct)

if __name__ == "__main__":
    main()