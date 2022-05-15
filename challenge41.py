#!/usr/bin/env python3
#Implement unpadded RSA message recovery oracle
from publickeycrypto import modinv, Rsa, int2bytes
from hashing import sha1

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
# simulate server response
# reject if hash of ciphertext exists
# decrypt using the rsa params if it's a new hash
def server_decrypt(ct, hashlist, rsa):
    hashed = sha1(str(ct)).hexdigest()
    pt = 'Hash of ciphertext already exists!'
    if hashed not in hashlist:
        pt = rsa.decrypt(ct)
        hashlist.append(hashed)
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
    # simulating first hash, to avoid making a server
    hashlist = ['b0dcac10027e5b2333894eb46cdf21a0c5851349']

    # encrypt with rsa, and get public keypair
    ct, (e, N) = rsa.encrypt(pt)
    pt_response, hashlist = server_decrypt(ct, hashlist, rsa)
    #pt, hashlist = server_decrypt(ct, hashlist, rsa)
    print(pt_response)

    # create ct_forged
    # basically, 1 mod 5 = 6 mod 5 = 11 mod 5
    S = 5 # can be any random number > 1 mod N
    ct_forged = pow(S,e,N) * ct % N
    pt_response, hashlist = server_decrypt(ct_forged, hashlist, rsa)
    
    # to get real pt, pt = pt_forged * inv_S mod N
    inv_S = modinv(S, N)
    pt = (pt_response * inv_S) % N
    print(int2bytes(pt), hashlist)

if __name__ == "__main__":
    main()