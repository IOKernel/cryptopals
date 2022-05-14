#!/usr/bin/env python3
from publickeycrypto import modinv, Rsa
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def server_decrypt(ct, hashlist):
    
    return pt, hashlist
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
# will not implement server-client connections with MITM
# and will instead precompute values to focus on the crypto
def main():
    pt = "{time: 1356304276,social: '555-55-5555'}"
    rsa = Rsa()
    # hash list of cipher blobs
    hashlist = []
    # encrypt with rsa, and get public keypair
    ct, (e, N) = rsa.encrypt(pt)
    print(ct)
if __name__ == "__main__":
    main()