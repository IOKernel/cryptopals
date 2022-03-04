#!/usr/bin/env python3
# Implementing the MT19937 Mersenne Twister RNG
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
        return self._extract_number()# / (2**self.w)
        


def main():
    seed = 12345
    a = Random(seed)
    print(f"{a.random()}")
            
if __name__ == "__main__":
    main()
