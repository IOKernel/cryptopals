#!/usr/bin/env python3
# --------------------------------------------------------
# ----------------------- imports ------------------------
# --------------------------------------------------------
from publickeycrypto import Dsa, modinv
from hashing import sha1

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    dsa = Dsa()
    m1 = "Hello, world"
    m2 = "Goodbye, world"

    # case 1: g = 0
    #! Note: had to disable r and s bounds checking in Dsa class
    #! to allow for r and s to be 0
    print("\nCase 1: g = 0")
    dsa.g = 0
    priv_key, pub_key = dsa.generate_keypair()
    print(f"priv_key: {priv_key}\npub_key: {pub_key}")
    (r, s) = dsa.sign(m1)
    print(f"r: {r}")
    print(f"s: {s}")
    # verify signature
    md1 = int(sha1(m1).hexdigest(), 16)
    print(f"Verify signature: {dsa.verify(md1, r, s)}") # True
    print(f"Verify signature: {dsa.verify(153123, r, s)}") # True
    print(f"Verify signature: {dsa.verify(1323213123123, r, s)}") # True

    # case 2: g = p + 1
    print("\nCase 2: g = p + 1")
    dsa.g = dsa.p + 1
    priv_key, pub_key = dsa.generate_keypair()
    print(f"priv_key: {priv_key}\npub_key: {pub_key}")
    (r, s) = dsa.sign(m1)
    print(f"r: {r}")
    print(f"s: {s}")
    # verify signature
    md2 = int(sha1(m2).hexdigest(), 16)
    print(f"Verify signature: {dsa.verify(md2, r, s)}") # True
    print(f"Verify signature: {dsa.verify(153123, r, s)}") # True
    print(f"Verify signature: {dsa.verify(1323213123123, r, s)}") # True

    # generate magic (r, s) pair that will validate any message
    # z is any number
    z = 15
    r = pow(pub_key, z, dsa.p) % dsa.q
    s = r * modinv(z, dsa.q) % dsa.q
    print(f"r: {r}")
    print(f"s: {s}")
    # verify signature
    print(f"Verify signature: {dsa.verify(md2, r, s)}") # True
    print(f"Verify signature: {dsa.verify(153123, r, s)}") # True
    print(f"Verify signature: {dsa.verify(1323213123123, r, s)}") # True

if __name__ == "__main__":
    main()