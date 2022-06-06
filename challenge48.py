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
from Crypto.Util import number
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def oracle(rsa: Rsa, ct: int) -> bool:
    """
    input: rsa = Rsa object
           ct = ciphertext
    output: parity of ct, True if even, False if odd
    """
    modBits = number.size(rsa.n)
    k = number.ceil_div(modBits,8)
    pt = rsa.decrypt(ct)
    pt = int2bytes(pt).rjust(k, b'\x00')
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

    s = n // (3*B)
    # step 2a
    s = single_s(rsa, ct, s, B)
    M = update_M(M, s, B, n)

    while True:
        (a, b) = M[0]
        if a > b:
            print(f"M: {M}")
        if a == b: # step 4
            return int2bytes(a)
        if len(M) > 1: # step 2b
            print("-"*200)
            s = single_s(rsa, ct, s + 1, B)
        if len(M) == 1: # step 2c
            s = next_s(rsa, ct, s, M, B)
        M = update_M(M, s, B, n)

def single_s(rsa: Rsa, ct: int, s: int, B: int) -> int:
    """
    input: rsa = Rsa object
           ct = ciphertext
           B = 2**(n.bitlength()-16)
           n = modulus
    output: s
    """
    print(f"[*] Single s:")
    e, n = rsa.getPubKey()

    while True:
        if oracle(rsa, (ct * pow(s, e, n)) % n):
            print(f"[*] s: {s}")
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
    print(f"[*] Next s:")
    e, n = rsa.getPubKey()
    a, b = M[0]

    r = ceildiv((2 * ((b*s) - (2*B))) , n)

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
    print(f"[*] Updating M:")
    M_new = []
    for (a, b) in M:
        r_lower = ceildiv((a * s - 3 * B + 1) , n)
        r_upper = ceildiv((b * s - 2 * B) , n)

        if r_lower == r_upper:
            r_upper += 1

        for r in range(r_lower, r_upper):
            lb = max(a, ceildiv(2 * B + r * n, s), 2*B)
            ub = min(b, (3 * B - 1 + r * n) // s, 3*B)
            # add the intersection of the current range and the new range
            M_new = intersect(M_new, (lb, ub))

    print(f"[*] M: {M_new}")
    return M_new

def intersect(M: list, M_new: tuple) -> list:
    lb, ub = M_new
    if len(M) == 0:
        return [(lb, ub)]
    for i, (a, b) in enumerate(M):
        if lb <= a <= ub or lb <= b <= ub:
            lb = min(a, lb)
            ub = max(b, ub)
            M[i] = (lb, ub)
            return M
    M.append((lb, ub))
    return M

def ceildiv(a: int, b: int) -> int:
    return -(-a // b)
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    rsa = Rsa(1024) # 2048 bit modulus size
    e, n = rsa.getPubKey()

    pt = b"this is a longer message test. But it's not a problem. It's just a test."
    pt = PKCS1_v1_5_pad(pt, n, MODE=2)
    ct, _ = rsa.encrypt(pt)
    pt_new = b'\x00' + break_rsa_parity_oracle(rsa, ct)

    print(f"[*] Plaintext (original): {pt}")
    print(f"[*] Plaintext (found):    {pt_new}")

    if pt == pt_new:
        print("\033[92m[*] Passed!\033[0m")
    else:
        print("\033[91m[*] Failed.\033[0m")


if __name__ == "__main__":
    main()