#!/usr/bin/env python3
from Crypto.Util.number import getPrime
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def invmod(a,b):
    # also a possible way to find the inverse since python 3.8
    return pow(a, -1, b)

def egcd(a,b):
    # more info on the algorithm found below
    # https://www.csee.umbc.edu/~chang/cs203.s09/exteuclid.shtml
    # d is the gcd, should be 1 for co-primes
    # s is the inverse mod of a mod b
    if b == 0:
        return (a,1,0)
    d1, s1, t1 = egcd(b, a%b)
    d = d1
    s = t1
    t = s1 - (a//b)*t1
    return (d,s,t)

def modinv(a,b):
    d, s, t = egcd(a, b)
    if d == 1:
        while s < 0:
            s += b
        return s
    raise ValueError(f"gcd(a,b) != 1")

class Rsa():
    def __init__(self, primeSize = 512, e = 3):
        self.p = getPrime(primeSize)
        self.q = getPrime(primeSize)
        while self.p == self.q:
            self.q = getPrime(primeSize)
        self.n = self.p * self.q
        # currently the code fails if invmod(3,totient) doesnt exist
        self.e = e
        self._keygen()

    def _keygen(self):
        et = (self.p-1) * (self.q-1)
        self.d = modinv(self.e, et)
        self.publickey = [self.e, self.n]
        self.privatekey = [self.d, self.n]

    def getPubKey(self):
        return self.publickey

    def getPrivKey(self):
        return self.privatekey
        
    def encrypt(self, m: int) -> int:
        if type(m) is str:
            m = m.encode()
        if type(m) is bytes:
            m = int(m.hex(),16)
        return pow(m, self.e, self.n) 

    def decrypt(self, c: int) -> int:
        return pow(c,self.d,self.n)
    
    def decrypt2bytes(self, c: int) -> bytes:
        return bytes.fromhex(hex(self.decrypt(c))[2:])
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    rsa = Rsa(512)
    ct = rsa.encrypt('test')
    print(f"ct: {ct}")
    pt = rsa.decrypt2bytes(ct)
    print(f"pt: {pt}")

if __name__ == "__main__":
    main()