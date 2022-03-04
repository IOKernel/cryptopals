#!/usr/bin/env python3
from utils import xor, ans_check

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
def main():
    cleartext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b'ICE' 
    # change the answer to a hex string
    result = bytes.hex(xor(cleartext.encode(), key))
    answer = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    # colored answer checker :)
    ans_check(answer, result)

if __name__ == "__main__":
    main()