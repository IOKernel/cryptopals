#!/usr/bin/env python3
from string import ascii_letters
import os
from utils import xor
# Adding numerals to the dataset
ascii_alphanumerals = ascii_letters + "123456890:.,?!"

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def get_score(message: str) -> int:
    '''
    a function that takes input string and using letter 
    frequency it scores it. The closer the score is 
    to 1.00, the more realistic.
    '''
    score = 0
    freq = {'a': 0.0812, 'b': 0.0149, 'c': 0.0271, 'd': 0.0432,
    'e': 0.1202, 'f': 0.0230, 'g': 0.0202, 'h': 0.0592, 'i': 0.0731,
    'j': 0.001, 'k': 0.0069, 'l': 0.0398, 'm': 0.0261, 'n': 0.0695,
    'o': 0.0768, 'p': 0.0182, 'q': 0.0011, 'r': 0.0602, 's': 0.0628,
    't': 0.091, 'u': 0.0288, 'v': 0.0111, 'w': 0.0209, 'x': 0.0017,
    'y': 0.0211, 'z': 0.0007, ' ': .1}
    for c in message:
        score += freq.get(c, 0) #if it is not an alphabet, give it a score of 0
    return score

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
def main():
    highestscore = 0
    # open the provided file
    dirname = os.path.dirname(__file__)
    path = os.path.join(dirname, 'challenge4-text.txt')
    with open(path) as f:
        for line in f:
            # strip the lines from the newline character \n
            line = bytes.fromhex(line.strip())
            for c in ascii_alphanumerals:
                #convert the character to an integer to use it in the strxor_c function
                result = xor(line, c.encode())
                #decode 'UTF-8' from bytes to string of text
                #if it throws an error give it a value of 0 (likely junk data)
                try:
                    result = result.decode()
                except UnicodeDecodeError:
                    result = ' '
                score = get_score(result)
                # to store the highest  scored combination. To be shown at the end of script
                if (score > highestscore):
                    highestscore = score
                    output = 'Character:'+c+"\nXOR'd output: "+result+'score ='+str(score)
                    original_line = line
    print('Original line:', original_line)
    print(output)

if __name__ == "__main__":
    main()