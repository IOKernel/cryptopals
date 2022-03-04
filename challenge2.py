#!/usr/bin/env python3
from utils import ans_check

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
'''
    Input: String a, String b
    Function: XORs a and b if equal sized string
    Output: xored String
'''
def xor(x: str, y: str) -> str:
    if len(x) != len(y): 
        raise ValueError('string not of equal length')
    # use int(x, 16) to turn a hex string into an integer to xor
    return hex(int(x, 16)^int(y, 16))

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
def main():
    x = '1c0111001f010100061a024b53535009181c'
    y = '686974207468652062756c6c277320657965'
    result = xor(x, y)
    answer = '746865206b696420646f6e277420706c6179'
    ans_check(answer, result[2:])

if __name__ == '__main__':
    main()