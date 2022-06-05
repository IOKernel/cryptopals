#!/usr/bin/env python3
"""
RSA padding oracle attack:
    This was a hard challenge, and the solution doesn't 
    work all the time. I'm not sure why. 
"""
# --------------------------------------------------------
# ----------------------- imports ------------------------
# --------------------------------------------------------
from publickeycrypto import Rsa, int2bytes
from padding import PKCS1_v1_5_pad
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def oracle(rsa: Rsa, ct: int) -> bool:
    """
    input: rsa = Rsa object
           ct = ciphertext
    output: parity of ct, True if even, False if odd
    """
    pt = rsa.decrypt(ct)
    pt = int2bytes(pt).rjust(32, b'\x00')
    return pt[0] == 0 and pt[1] == 2

def break_rsa_parity_oracle(rsa: Rsa, ct: int) -> bytes:
    """
    input: rsa = Rsa object
           ct = ciphertext
    output: plaintext
    """
    e, n = rsa.getPubKey()

    B = 2**(n.bit_length()-16) # or n.bit_length()-16
    M = [(B*2, B*3 - 1)] # [(lb, ub)]

    s = first_s(rsa, ct, B, n)
    M = update_M(M, s, B, n)

    while True:
        a, b = M[0]
        if a > b:
            print(f"M: {M}")
            exit(1)
        if a == b:
            return int2bytes(a)

        s = next_s(rsa, ct, s, M, B)
        M = update_M(M, s, B, n)

def first_s(rsa: Rsa, ct: int, B: int, n: int) -> int:
    """
    input: rsa = Rsa object
           ct = ciphertext
           B = 2**(n.bitlength()-16)
           n = modulus
    output: s
    """
    e, n = rsa.getPubKey()
    s = n // (3*B)

    while True:
        if oracle(rsa, (ct * pow(s, e, n)) % n):
            return s
        s += 1

def next_s(rsa: Rsa, ct: int, s: int, M: list, B: int) -> tuple:
    """
    input: rsa = Rsa object
           ct = ciphertext
           s = current s
           M = [(lb, ub)]
           B = 2**(256-16)
    output: s, c
    """
    e, n = rsa.getPubKey()
    a, b = M[0]

    r = (2 * ((b*s) - (2*B))) // n

    while True:
        slow = ceildiv(2 * B + r * n, b)
        shigh = ceildiv(3 * B + r * n, a)
        for s in range(slow, shigh):
            if oracle(rsa, (ct * pow(s, e, n)) % n):
                return s
        r += 1

def update_M(M: list, s: int, B: int, n: int) -> list:
    """
    input: M = [(lb, ub)]
           s = current s
           B = 2**(256-16)
    output: M = [(lb, ub)]
    """
    a, b = M[0]
    r_lower = ceildiv((a * s - 3 * B + 1) , n)
    #r_upper = ceildiv((b * s - 2 * B) , n)

    lb = max(a, ceildiv(2 * B + r_lower * n, s), 2*B)
    ub = min(b, (3 * B - 1 + r_lower * n) // s, 3*B - 1)
    return [(lb, ub)]

def ceildiv(a: int, b: int) -> int:
    return -(-a // b)
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    rsa = Rsa(128) # 256 bit modulus size
    e, n = rsa.getPubKey()

    pt = b"hell world"
    pt = PKCS1_v1_5_pad(pt, n, MODE=2)
    ct, _ = rsa.encrypt(pt)
    print(f"[*] Plaintext (original): {pt}")
    pt = b'\x00' + break_rsa_parity_oracle(rsa, ct)
    print(f"[*] Plaintext (found):    {pt}")

if __name__ == "__main__":
    main()