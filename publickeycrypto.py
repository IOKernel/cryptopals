# might be better to move into mathutils.py
from Crypto.Util.number import getPrime
from hashing import sha1
from os import urandom
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

def int2bytes(m: int, byteorder = 'big') -> bytes:
    return m.to_bytes(length=(max(m.bit_length(), 1) + 7) // 8, byteorder=byteorder)

def DSA_recover_x_from_k(k:int, r:int, s:int, md:int):
    """
    Recover private key (x) from signature (r, s) and message digest (md)
    returns recovered private key
    """
    r_inv = modinv(r, Dsa().q)
    x = r_inv * ((k * s) - md) % Dsa().q
    return x

class Rsa():
    def __init__(self, primeSize = 512, e = 3):
        self.e = e

        self.p = getPrime(primeSize)
        while self.p % self.e == 1:
            self.p = getPrime(primeSize)

        self.q = getPrime(primeSize)
        while (self.p == self.q) or (self.q % self.e == 1):
            self.q = getPrime(primeSize)

        self.n = self.p * self.q
        # currently the code fails if invmod(3,totient) doesnt exist
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
        # returns ct + public key (e, n)
        if type(m) is str:
            m = m.encode()
        if type(m) is bytes:
            m = int(m.hex(),16)
        return pow(m, self.e, self.n), self.publickey

    def decrypt(self, c: int) -> int:
        return pow(c,self.d,self.n)
    
    def decrypt2bytes(self, c: int) -> bytes:
        return bytes.fromhex(hex(self.decrypt(c))[2:])

class Dsa:
    def __init__(self, x:int = 0, y:int = 0):
        # p, q and g are defined in FIPS 186-4
        self.p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
        self.q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
        self.g = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
        self.x = x
        self.y = y

    def generate_keypair(self):
        """
            input: none
            output: (x, y) = public key
        """
        # returns (x, y)
        x = int(urandom(16).hex(), 16) % (self.q - 1)
        # assert that x is in range [1, q-1]
        assert 1 < x < self.q
        y = pow(self.g, x, self.p) 
        return (x, y)

    def sign(self, m: str):
        """
            input: m = message to be signed (string)
            output: (r, s) = signature
        """
        # returns (r, s)
        if type(m) == str:
            md = sha1(m).hexdigest()
            md = int(md, 16)
        elif type(m) == int:
            md = m

        k = int(urandom(16).hex(), 16) % (self.q - 1)
        # assert that k is in range [1, q-1]
        assert 1 < k < self.q

        r = pow(self.g, k, self.p) % self.q
        # assert that r is in range [1, q-1]
        assert 1 < r < self.q

        s = (modinv(k, self.q) * (md + self.x * r)) % self.q
        # assert that s is in range [1, q-1]
        assert 1 < s < self.q

        return (r, s)

    def verify(self, md: int, r: int, s: int):
        """
            input:
            md = message digest (int)
            r = signature (int)
            s = signature (int)
            output: True if signature is valid, False otherwise
        """
        # returns True or False
        if 0 < r < self.q and 0 < s < self.q:
            w = modinv(s, self.q)
            u1 = (md * w) % self.q
            u2 = (r * w) % self.q
            v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
            return v == r