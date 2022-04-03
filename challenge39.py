#!/usr/bin/env python3
from Crypto.Util.number import getPrime
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def invmod(a,b):
    return pow(a, -1, b)

class Rsa():
    def __init__(self, primeSize = 512):
        self.p = getPrime(primeSize)
        self.q = getPrime(primeSize)
        while self.p == self.q:
            self.q = getPrime(primeSize)
        self.n = self.p * self.q
        # currently the code fails if invmod(3,totient) doesnt exist
        self.e = 3
        self._keygen()

    def _keygen(self):
        et = (self.p-1) * (self.q-1)
        self.d = invmod(self.e, et)
        self.publickey = [self.e, self.n]
        self.privatekey = [self.d, self.n]
    
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
    print(ct)
    pt = rsa.decrypt2bytes(ct)
    print(pt)

if __name__ == "__main__":
    main()