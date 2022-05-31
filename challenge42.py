#!/usr/bin/env python3
# Bleichenbacher's e=3 RSA Attack
# --------------------------------------------------------
    # PKCS1 v1.5 paper https://datatracker.ietf.org/doc/html/rfc2313
    # read https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
    # read https://words.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/

# --------------------------------------------------------
# ----------------------- imports ------------------------
# --------------------------------------------------------
from publickeycrypto import Rsa, int2bytes
from hashing import sha1
import re
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def verify_signature(m, s, e, n):
    # verify the signature
    # returns True if signature is valid
    D = "ASN.1SHA1"
    m = D + sha1(m).hexdigest() 
    m, _ = PKCS1_v1_5_pad(m.encode())
    m = int.from_bytes(m, 'big')
    if s > n:
        return False
    if pow(s, e, n) == m:
        return True
    return False

def bad_verify_signature(m, s, e, n):
    # verify the signature
    # returns True if signature is valid
    D = "ASN.1SHA1"
    m = D + sha1(m).hexdigest() 
    m, _ = PKCS1_v1_5_pad(m.encode())
    m = int.from_bytes(m, 'big')
    decrypted_signature = bytes.fromhex('000'+hex(pow(s, e, n))[2:])
    if s > n:
        return False
    # using regex to find the padding + hash identifier 
    finder = re.compile(b'\x00\x01[\xff]*\x00ASN\.1SHA1')
    # if matched, print the match
    if finder.match(decrypted_signature):
        return True
    else:
        return False

def rsa_sign(m, d, n):
    # returns signature of m
    m = sha1(m).hexdigest()
    # sha1 object identifier 
    # sha1_identifier = "{iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)}"
    # or
    # sha1_identifier = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    # but for convenience, we'll use SHA1 as the identifier

    D = "ASN.1SHA1"
    m = D + m

    # pad the hash with PKCS1_v1_5 padding
    padded_hash, pad_length = PKCS1_v1_5_pad(m.encode())
    print(f"padded hash: {padded_hash}")
    print(f"pad length: {pad_length}")

    m = int.from_bytes(padded_hash, 'big')
    s = pow(m, d, n)
    return s

# implement PKCS1_v1_5 padding function
def PKCS1_v1_5_pad(m):
    # pad the message with PKCS1_v1_5 padding
    # returns (padded_m, pad_length)
    # pad_length is the number of bytes added to the message
    # pad_length is always between 1 and 255
    pad_length = 256 - len(m) - 3
    padded_m = b"\x00\x01" + b"\xff" * pad_length + b"\x00" + m
    return (padded_m, pad_length)

# forge rsa signature with message m
def forge_signature(m, e):
    # forge the signature
    # returns forged signature
    D = "ASN.1SHA1"
    m = D + sha1(m).hexdigest()
    m = b"\x00\x01" + b"\xff" + b"\x00" + m.encode() + bytes(100)
    m = int.from_bytes(m, 'big')
    # forged signature s = cube root of m
    s =  iroot(m, e)[0]
    return s

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    m = b"hi mom"
    bit_size = 1024

    rsa = Rsa(bit_size)
    # get public key and private key
    e, n = rsa.getPubKey()
    d = rsa.getPrivKey()[0]

    # sign the message
    s = rsa_sign(m, d, n)
    # verify the signature
    print(f"signature: {int2bytes(s)}")
    # decrypt the signature
    print(f"decrypt signature: {bytes.fromhex('000'+hex(pow(s, e, n))[2:])}")
    print(f"verify signature: {bad_verify_signature(m, s, e, n)}")

    # forge the signature
    forged_s = forge_signature(m, e)
    print(f"forged signature: {long_to_bytes(forged_s)}")
    print(f"verify forged signature: {bad_verify_signature(m, forged_s, e, n)}")

if __name__ == "__main__":
    main()