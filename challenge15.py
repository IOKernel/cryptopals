#!/usr/bin/env python3
# PKCS#7 padding validation
from utils import ans_check
from padding import pkcs7_unpad

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    # case1
    ans_check(b"ICE ICE BABY", pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
    # case2
    try:
        ans_check(b"ICE ICE BABY\x05\x05\x05\x05", pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05"))
    except ValueError as err:
        print(err)
        ans_check(err.args[1], b"ICE ICE BABY\x05\x05\x05\x05")
    # case3
    try:
        ans_check(b"ICE ICE BABY\x01\x02\x03\x04", pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04"))
    except ValueError as err:
        print(err)
        ans_check(err.args[1], b"ICE ICE BABY\x01\x02\x03\x04")

if __name__ == "__main__":
    main()