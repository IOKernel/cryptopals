#!/usr/bin/env python3
# DSA: Digital Signature Algorithm
# FIPS 186-4 specifies L and N to have one of the values:
# (1024, 160) or (2048, 224)
# q = N-bit prime
# p = L-bit prime   | p = 1 (mod q) (p-1 = multiple of q)
# h = random integer in range [2 , p-2]
# g = generator     | g = h^((p-1)/q) (mod p)
# x = private key   | x = random integer in range [1 , q-1]
# y = public key    | y = g^x (mod p)
# k = random integer in range [1 , q-1]
# if r = 0 or s = 0, start with new k
# r = signature     | r = (g^k mod p) (mod q). 
# s = signature     | s = (k^-1 * (hash(m) + x*r)) (mod q)
# Note: Can use EEA or Fermat's little theorem to find k^-1
# m = message
# --------------------------------------------------------
# ----------------------- imports ------------------------
# --------------------------------------------------------
from hashing import sha1
from publickeycrypto import int2bytes, modinv
from os import urandom
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def recover_priv_key_DSA(k:int, r:int, s:int, md:int):
    """
    Recover private key (x) from signature (r, s) and message digest (md)
    returns recovered private key
    """
    r_inv = modinv(r, Dsa().q)
    x = r_inv * ((k * s) - md) % Dsa().q
    return x

def bruteforce_recover_priv_key_DSA(k_bitsize:int, r:int, s:int, md:int, pub_key:int):
    """
    Brute force to recover private key (x) from signature (r, s), message digest (md)
    and public key (y)
    returns recovered private key (x)
    """
    for k in range(2**k_bitsize):
        r_inv = modinv(r, Dsa().q)
        x = r_inv * ((k * s) - md) % Dsa().q

        r_gen = pow(Dsa().g, k, Dsa().p) % Dsa().q
        try:
            s_gen = (modinv(k, Dsa().q) * (md + x * r)) % Dsa().q
        except:
            continue
        if r_gen == r and s_gen == s:
            #print(f"Recovered private key: {x}")
            print(f"k: {k}")
            return x
    # another solution method:
    # generate pub_key then bruteforce values i * y mod p
    # until we have pub_key = y_given
    #     y_gen = pow(Dsa().g, x, Dsa().p)
    return None

# implement DSA
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

        return r, s, k # k not supposed to be returned, but for testing purposes

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

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    # note: to get the same message digest as the challenge,
    # you must add a newline to the end of the message
    m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    priv_key, pub_key = Dsa().generate_keypair()

    r, s, k = Dsa(priv_key, pub_key).sign(m)
    print("Signature (r, s):", (r, s))

    md = sha1(m).hexdigest()
    md = int(md, 16)
    print("Verification:", Dsa(priv_key, pub_key).verify(md, r, s))

    # get recovered key and check if it matches the original key
    recovered_priv_key = recover_priv_key_DSA(k, r, s, md)
    print("Recovered private key:", recovered_priv_key)
    print("Original private key:", priv_key)
    print("Recovered private key matches original key:", recovered_priv_key == priv_key)


    # ------------ CHALLENGE VARIABLES ------------
    print("----- CHALLENGE SOLUTION -----")
    # brute force to recover key
    priv_key_hash = "0954edd5e0afe5542a4adf012611a91912a3ec16"
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
    priv_key_re = bruteforce_recover_priv_key_DSA(k_bitsize=16, r=r, s=s, md=md, pub_key=y)
    priv_key_re = sha1(hex(priv_key_re)[2:]).hexdigest()
    print("Recovered private key (hex):", priv_key_re)
    print("Recovered private key matches original key:", priv_key_re == priv_key_hash)
    
if __name__ == "__main__":
    main()