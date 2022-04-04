#!/usr/bin/env python3
#E=3 RSA Broadcast attack
from publickeycrypto import Rsa, egcd
import gmpy2
# precision set to get all of the pt correctly (otherwise only partial pt)
gmpy2.get_context().precision = 4096
from gmpy2 import root
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def extended_gcd(a, b):
    x, y = 0, 1
    lastx, lasty = 1, 0

    while b:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y

    return (lastx, lasty, a)


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1

def crt(pairs):
    # chinese remainder theorem
    N = 1
    for _, n in pairs:
        N *= n
    
    # multiply the n's
    result = 0
    for c, n in pairs:
        m = N // n
        # why does t work and not s(the modinv)??
        _, _, t = egcd(n, m)
        result += c * m * t

    return result % N
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    message = b"RSA Broadcast Attack"
    EXPONENT = 3
    ct0, (e0, n0) = Rsa().encrypt(message)
    ct1, (e1, n1) = Rsa().encrypt(message)
    ct2, (e2, n2) = Rsa().encrypt(message)
    crt_list = [(ct0,n0), (ct1,n1), (ct2,n2)]

    c_result = crt(crt_list)

    # use gmpy2.root with 4096 precision
    M = int(root(c_result,EXPONENT))
    pt_text = bytes.fromhex(hex(M)[2:])
    print(pt_text)

if __name__ == "__main__":
    main()