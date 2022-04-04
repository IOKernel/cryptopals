#!/usr/bin/env python3
#E=3 RSA Broadcast attack
from publickeycrypto import Rsa, modinv
from gmpy2 import root
from binascii import unhexlify
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def crt(crt_list):
    # chinese remainder theorem
    ct_list = []
    n_list = []
    # make lists of c, e, and n values
    for pair in crt_list:
        ct_list.append(pair[0])
        n_list.append(pair[1])
    print(n_list)
    n_mul = 1
    for n in n_list:
        n_mul *= n
    # multiply the n's
    result = 0
    for i in range(len(ct_list)):
        m_s = n_mul//n_list[i]
        result += ct_list[i] * m_s * modinv(n_list[i], m_s)

    return result % n_mul
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
    print(c_result)

    M = int(root(c_result,3))
    pt_text = bytes.fromhex(hex(M)[2:])
    #print(pt_text)
    M = hex(M)[2:]
    print(unhexlify(M).decode('utf-8'))

if __name__ == "__main__":
    main()