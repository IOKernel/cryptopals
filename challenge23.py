#!/usr/bin/env python3
from utils import ans_check, Random

# --------------------------------------------------------
# ---------------------- constants -----------------------
# --------------------------------------------------------
w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253
lower_mask = (1<<r)-1
upper_mask = lower_mask ^ d

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def untemper(y5):
    '''
        inverses the MT operations of right and left shifting
    '''
    def _recover_y1(y2):
        # example, y2 = 3013019064
        # recover, y1 = 3011605910
        ybin = bin(y2)[2:].zfill(32)
        recovery = ybin[:u]
        for i in range(w-u):
            recovery += str(int(ybin[i+u])^int(recovery[i]))
        recovery = int(recovery,2)
        return recovery

    def _recover_y2(y3):
        # example, y3 = 982995384
        # recover, y2 = 3013019064
        and_const = bin(0x9D2C5680)[2:]
        ybin = bin(y3)[2:].zfill(32)
        # last 15 bits
        recovery = ybin[-s:]
        # remaining bits
        for index in range(w-s):
            and_bit = int(and_const[-index-s-1])
            xored_bit = int(ybin[-index-s-1])
            recovery_bit = int(recovery[-index-1])
            recovery = str((and_bit & recovery_bit)^xored_bit) + recovery
        recovery = int(recovery, 2)
        return recovery

    def _recover_y3(y4):
        # example, y4 = 2454933944
        # recover, y3 = 982995384
        and_const = bin(0xEFC60000)[2:]
        ybin = bin(y4)[2:].zfill(32)
        # last 15 bits
        recovery = ybin[-t:]
        # remaining bits
        for index in range(w-t):
            and_bit = int(and_const[-index-t-1])
            xored_bit = int(ybin[-index-t-1])
            recovery_bit = int(recovery[-index-1])
            recovery = str((and_bit & recovery_bit)^xored_bit) + recovery
        recovery = int(recovery, 2)
        return recovery

    def _recover_y4(y5):
        # example, y5 = 2454943020
        # recover, y4 = 2454933944
        ybin = bin(y5)[2:].zfill(32)
        recovery = ybin[:l]
        for i in range(32-l):
            recovery += str(int(ybin[i+l])^int(recovery[i]))
        recovery = int(recovery,2)
        return recovery

    y4 = _recover_y4(y5)
    y3 = _recover_y3(y4)
    y2 = _recover_y2(y3)
    y1 = _recover_y1(y2)
    return y1
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    mt_recovered = [0]*n
    seed = 1953125
    rand = Random(seed)
    for i in range(n):
        mt_recovered[i] = untemper(rand.random())
    # generate a new rand generator with our MT
    new_rand_gen = Random(MT = mt_recovered)
    # check if generation is identical
    for _ in range(5):
        ans_check(rand.random(), new_rand_gen.random())
    

if __name__ == "__main__":
    main()