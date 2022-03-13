#!/usr/bin/env python3
from Crypto.Cipher import AES
from os import urandom
import os
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
BLOCKSIZE = 16
def xor(a: bytes, b: bytes, repeat = True) -> bytes:
    '''
        to get the key to roll over, the module operator
        is used over the length of the key, 
        so string_pos MOD key_length
        ex: 0%3 = 0, 1%3 = 1, 2%3 = 2, 3%3 = 0, etc..
    '''
    xored = []
    if repeat:
        for char_pos, c in enumerate(a):
            xored.append(c ^ b[char_pos%len(b)])
    else:
        if len(a)<len(b):
            b, a = a, b
            for char_pos in range(len(b)):
                xored.append(a[char_pos] ^ b[char_pos])
            for char_pos in range(len(b), len(a)):
                xored.append(a[char_pos])
    return bytes(xored)


def ans_check(answer, result) -> str:
    # compare if results match
    if (result == answer):
        print('\033[32m'+"Passed\033[0m")
        return True
    else:
        print('\033[91m'+"FAILED\033[0m")
        return False

def read(filename: str) -> str:
    '''opening the file and reading the ciphertext'''
    dirname = os.path.dirname(__file__)
    path = os.path.join(dirname, filename)
    with open(path) as f:
        content = f.read()
    return content


def get_blocks(data: bytes, bs: int = 16) -> list:
    return [data[i:i+bs] for i in range(0, len(data), bs)]

def block_bit_flip(block: bytes, guess: int, flip_pos: int, new_byte: int) -> bytes:
    flipped_byte = bytes([block[flip_pos] ^ guess ^ new_byte])
    return block[:flip_pos] + flipped_byte + block[flip_pos+1:]

def bitstring_to_bytes(s: str) -> bytes:
    # takes binary string and converts it to bytes
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

def _bytes_to_binary(msg: bytes) -> str:
        # converts the bytes to binary str
        if msg:
            to_int = int.from_bytes(msg, 'big')
            return bin(to_int)[2:].rjust(len(msg)*8,'0')
        else:
            return ''
class Random():
    def __init__(self, input_seed = 0, MT = False):
        # initializing values
        self.w, self.n, self.m, self.r = 32, 624, 397, 31
        self.a = 0x9908B0DF
        self.u, self.d = 11, 0xFFFFFFFF
        self.s, self.b = 7, 0x9D2C5680
        self.t, self.c = 15, 0xEFC60000
        self.l = 18
        self.f = 1812433253
        self.lower_mask = (1<<self.r)-1
        self.upper_mask = self.lower_mask ^ self.d
        self.seed = input_seed
        if not MT:
            self.MT = [0]*self.n
            self.index = self.n + 1
            self._seed_mt(self.seed)
        else:
            self.MT = MT
            self.index = self.n
        
    def _seed_mt(self, seed):
        self.MT[0] = seed
        self.index = self.n
        for i in range(1, self.n):
            self.MT[i] = ((self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i)&self.d)
    

    def _extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise ValueError('Generator was never seeded')
            self._twist()
        y = self.MT[self.index]
        y = y ^ ((y>>self.u)&self.d)
        y = y ^ ((y<<self.s)&self.b)
        y = y ^ ((y<<self.t)&self.c)
        y = y ^ (y>>self.l)
        self.index += 1
        return y & self.d
        # to compute in batches
        # y = self.MT
        # y = [y_val ^ ((y_val>>self.u)&self.d) for y_val in y]
        # y = [y_val ^ ((y_val<<self.s)&self.b) for y_val in y]
        # y = [y_val ^ ((y_val<<self.t)&self.c) for y_val in y]
        # y = [y_val ^ (y_val>>self.l) for y_val in y]
        # return [y_val & self.d for y_val in y][self.index]

    def _twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2):
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0


    def random(self):
        return self._extract_number()# / (2**self.w) # to output numbers {0,1}
        