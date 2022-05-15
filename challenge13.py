#!/usr/bin/env python3
# ECB cut-and-paste
from utils import ans_check
from aes import (
    aes_ecb_encrypt, 
    aes_ecb_decrypt, 
    random_bytes_gen
    )
from padding import pkcs7_pad, pkcs7_unpad
from os import urandom
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
key = random_bytes_gen(16)
# for testing
#key = b"\x87\xb4\x80\x9e\x80'\x10\xd2\xfe}\xd5\x99\xdf;P\xac"
def parse_cookie(cookie: str) -> dict:
    cookie_dict = {}
    parsed_cookie = cookie.split('&')
    for item in parsed_cookie:
        cookie_dict[item.split('=')[0]] = item.split('=')[1]
    return cookie_dict

def encode_cookie(cookie_dict: dict) -> str:
    cookie = ''
    for value in cookie_dict:
        cookie += f'{value}={cookie_dict[value]}&'
    return cookie[:-1]

def profile_for(email: str) -> str:
    if '=' in email or '&' in email:
        raise ValueError("Cant use & or =")
    profile = {}
    profile['email'] = email
    profile['role'] = 'user'
    cookie = encode_cookie(profile)
    return cookie

def perform_tests():
    cookie_input = 'foo=bar&baz=qux&zap=zazzle'
    cookie_parse_ans = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
        }
    cookie_dict = parse_cookie(cookie_input)
    print('Parse check: ', end='')
    ans_check(cookie_dict, cookie_parse_ans)
    # profile creation tests
    profile_check = "foo@bar.com"
    profile_check_ans = 'email=foo@bar.com&role=user'
    profile_check_dict = profile_for(profile_check)
    print('profile_for check: ', end='')
    ans_check(profile_check_dict, profile_check_ans)

def encrypt_profile(user: str) -> list:
    user =  pkcs7_pad(user)
    return [aes_ecb_encrypt(user, key), key]

def decrypt_profile(ciphertext: bytes, key: bytes = key) -> dict:
    plaintext = aes_ecb_decrypt(ciphertext, key)
    plaintext = pkcs7_unpad(plaintext).decode()
    return parse_cookie(plaintext)

def profile_oracle(email: str) -> bytes:
    cookie = profile_for(email)
    ciphertext, key = encrypt_profile(cookie)
    print(f'Decrypted Cookie: {decrypt_profile(ciphertext, key)}')
    return ciphertext

def get_cipherblocks(oracle_input: str) -> list:
    ciphertext = profile_oracle(oracle_input)
    cipher_blocks = []
    for i in range(0, len(ciphertext), 16):
        cipher_blocks.append(ciphertext[i:i+16])
    return cipher_blocks

# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
# basically we need to first get a block of encryptred data
# where we have '&role=admin' and then try to replace it in
# a ciphertext returned by the oracle
def main():
    # cookie parse function check
    perform_tests()
    # format is email=foo@bar.com&role=user
    # we want the last block to be 'user+padding' so, 'email=AAAA&role=' is 16 bytes
    # b'\x158\x90\xba\xbf\x86\xad;\xc5\xaf\xb5\x00\xd5\xb4\xd7\xff' = user+padding
    # user_byte = get_cipherblocks('A'*4)[-1]
    # after getting the user_byte, we need to find the admin_byte
    # so the blocks are ['email=' + "A"*10] [pad('admin')] [pad(&role=user)]
    # b'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'admin + padding
    # b'h/#\x9c\x88%\xd6>\x88\x1b\x17\xc9w|\xf3.' admin + padding
    admin_input = b'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
    admin_byte = get_cipherblocks('A'*10 + admin_input.decode())[1]
    legit_blocks = get_cipherblocks('A'*10 + '@gmail.com')
    crack = legit_blocks[0] + legit_blocks[1] + admin_byte
    print(decrypt_profile(crack))

if __name__ == "__main__":
    main()