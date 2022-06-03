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
def oracle(rsa: Rsa, ct: int) -> bool:
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
    # so if we double the ciphertext, c = c * pow(2, e, n). then:
    # the plaintext is also doubled, pt = pt * 2
    e, n = rsa.getPubKey()

    lower_bound, upper_bound = 1, n - 1
    iteration = 0
    multiplier = pow(2, e, n)
    print("[*] Trying to find the plaintext...")
    while lower_bound < upper_bound: # or for _ in range(1024)
        print("-" * 50)
        print(f"[*] Iteration {iteration}")
        iteration += 1

        mid = (lower_bound + upper_bound) // 2
        ct *= multiplier
        # I can't get it to return correct last byte b'a'
        if oracle(rsa, ct):
            upper_bound = mid - 1
        else:
            lower_bound = mid + 1
        print(int2bytes(upper_bound))

    return int2bytes(upper_bound)
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