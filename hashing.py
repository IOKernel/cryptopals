import struct
class sha1():
    def __init__(self, msg: bytes, h_vals: list = [], padding = ''):
        if type(msg) is str:
            self.message = msg.encode()
        else:
            self.message = msg
        self.h = h_vals.copy()
        self.padding = padding
        if not self.h:
            self.h = [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
                ]
        
        # initializing constants:
        self.ml = bin(len(self.message) * 8)[2:].rjust(64, '0')
        #self.ml = len(self.message) * 8
        self.wrap_32 = 2**32
        self.H = 0
        ## pre-processing:
        klen = 448 - ((len(self.message)*8)+1)%512
        self._bytes_to_binary()
        # padding can be provided for length extension attacks
        # forged padding of key + og_str + padding_bytes + new_str
        if not self.padding:
            self.padding = '1' + '0'*klen + self.ml
        self.message += self.padding
        self._process()


    def _break_chunks(self, data: int, chunk_size: int) -> list:
        if type(data) is int:
            data = bin(data)[2:].rjust(512, '0')
        return [int(data[i:i+chunk_size],2) for i in range(0, len(data), chunk_size)]

    def _left_rotate(self, data: int, rot_val: int):
        # rotates bit vals
        return ((data << rot_val)|(data >> (32 - rot_val))) % self.wrap_32

    def _bytes_to_binary(self):
        # converts the string to binary str
        if self.message:
            to_int = int.from_bytes(self.message, 'big')
            self.message = bin(to_int)[2:].rjust(len(self.message)*8,'0')
        else:
            self.message = ''
            
    def hexdigest(self):
        return hex(self.H)[2:]

    def bytes(self):
        # could use bitstring_to_bytes from chal28
        return self.H.to_bytes((self.H.bit_length() + 7) // 8, 'big') or b'\0'

    ## process message in 512-bit chunks
    def _process(self):
        chunks_512 = self._break_chunks(self.message, 512)
        for chunk in chunks_512:
            w = [0]*80
            w[0:16] = self._break_chunks(chunk, 32)
            for i in range(16,80):
                w[i] = self._left_rotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1) % self.wrap_32
            # Initialize hash value for this chunk: 
            a, b, c, d, e = self.h
            # main loop
            for i in range(80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                temp = (self._left_rotate(a,5) + f + e + k + w[i]) % self.wrap_32
                e = d 
                d = c 
                c = self._left_rotate(b, 30) % self.wrap_32
                b = a 
                a = temp 
            self.h[0] = (self.h[0] + a) % self.wrap_32
            self.h[1] = (self.h[1] + b) % self.wrap_32
            self.h[2] = (self.h[2] + c) % self.wrap_32
            self.h[3] = (self.h[3] + d) % self.wrap_32
            self.h[4] = (self.h[4] + e) % self.wrap_32
        # digests the final hash value (big-endian) as a 160-bit number:
        self.H = self.h[0]<<128 | self.h[1]<<96 | self.h[2]<<64 | self.h[3]<<32 | self.h[4]
        

# MD4 implementation from
# https://github.com/kangtastic/

class MD4:
    """An implementation of the MD4 hash algorithm."""

    width = 32
    mask = 0xFFFFFFFF

    # Unlike, say, SHA-1, MD4 uses little-endian. Fascinating!
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, msg=None):
        """:param ByteString msg: The message to be hashed."""
        if msg is None:
            msg = b""

        self.msg = msg

        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)
        # Process the message in successive 512-bit chunks.
        self._process([msg[i : i + 64] for i in range(0, len(msg), 64)])

    def __repr__(self):
        if self.msg:
            return f"{self.__class__.__name__}({self.msg:s})"
        return f"{self.__class__.__name__}()"

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return self.h == other.h

    def bytes(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack("<4L", *self.h)

    def hexbytes(self):
        """:return: The final hash value as hexbytes."""
        return self.hexdigest().encode

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


def main():
    # Import is intentionally delayed.
    import sys

    if len(sys.argv) > 1:
        messages = [msg.encode() for msg in sys.argv[1:]]
        for message in messages:
            print(MD4(message).hexdigest())
    else:
        messages = [b"", b"The quick brown fox jumps over the lazy dog", b"BEES"]
        known_hashes = [
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "1bee69a46ba811185c194762abaeae90",
            "501af1ef4b68495b5b7e37b15b4cda68",
        ]

        print("Testing the MD4 class.")
        print()

        for message, expected in zip(messages, known_hashes):
            print("Message: ", message)
            print("Expected:", expected)
            print("Actual:  ", MD4(message).hexdigest())
            print()
