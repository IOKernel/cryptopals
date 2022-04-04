#!/usr/bin/env python3
#E=3 RSA Broadcast attack
from publickeycrypto import Rsa
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    message = b"RSA Broadcast Attack"
    ct1 = Rsa().encrypt(message)
    ct2 = Rsa().encrypt(message)
    ct2 = Rsa().encrypt(message)

    print(ct1,ct2,ct3)

if __name__ == "__main__":
    main()