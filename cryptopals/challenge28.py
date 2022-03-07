#!/usr/bin/env python3
from sha1 import sha1
from aes import random_bytes_gen
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def sha1mac(message: bytes) -> bytes:
    #key = random_bytes_gen(16)
    key = b'\xa0f\xa6\xe5\x16h\n\xf3\xd9\x84\x0c\xefz\x05\xea_'
    return sha1(key+message)
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    digest = sha1mac(b'test')
    print(digest)

if __name__ == "__main__":
    main()