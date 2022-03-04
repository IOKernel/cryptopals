#!/usr/bin/env python3
from base64 import b64decode
from utils import xor
import os

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

def hamming_distance(x: bytes, y: bytes) -> int:
    '''
        A function that takes two bytes or strings, x and y.
        and returns the integer number of differing bits
        in the text or AKA the hamming distance.
        #! not 100% on the code. But it's working
    '''
    differences = 0
    # accepts input whether it's a string or single byte
    if type(x) == str and type(y) == str: 
        xbit_array = str2bitArray(x)
        ybit_array = str2bitArray(y)
    else:
        xbit_array = byte2bitArray(x)
        ybit_array = byte2bitArray(y)

    for byte, byte_val in enumerate(xbit_array):
        for bit, bit_val in enumerate(byte_val):
            try:
                if bit_val != ybit_array[byte][bit]:
                    differences += 1
            except:
                differences += 1
    return differences

def str2bitArray(string: str) -> list:
    '''
        A function that takes a string and returns the bit 
        values of the strings in a per character list
    '''
    bit_array = []
    for c in string:
        bit = bin(ord(c))
        bit_array.append(bit)
    return bit_array

def byte2bitArray(byte_array: bytes) -> list:
    '''
        A function that takes bytes and returns the 
        bit values of bytes in a list
    '''
    bit_array = []
    for byte_val in byte_array:
        bit = bin(byte_val)
        bit_array.append(bit)
    return bit_array

def smallest_hamming_distance(cipher_bytes: bytes) -> list:
    '''
        A function that when given a ciphertext, uses the
        hamming_distance() function and keeps a list of distances
        for different KEYSIZES.
        The function compares consecutive KEYSIZE number of bytes
        and then normalizes the result by the number of iterations
        or chunks it had to compare, to not give any large keysizes
        more advantage
    '''
    distances = []
    for KEYSIZE in range(2,40):
        distance = 0
        for i in range(0, len(cipher_bytes), KEYSIZE):
            iterations = len(cipher_bytes)/KEYSIZE
            x_byte = cipher_bytes[i:i+KEYSIZE]
            y_byte = cipher_bytes[i+KEYSIZE:i+(KEYSIZE*2)]
            distance += hamming_distance(x_byte, y_byte)/KEYSIZE
        distances.append([KEYSIZE, distance/iterations])
    # sorts the distances by the normalized distance value ascendingly
    sorted_distances = sorted(distances, key=lambda x: x[1])
    print('Smallest normalized distance is {:.3f} '.format(sorted_distances[0][1]), end='')
    print('At KEYSIZE =', sorted_distances[0][0])
    return sorted_distances

def split_bytes(cipher_bytes: bytes, KEYSIZE: int) -> list:
    '''
        A function that splits bytes into chunks of bytes
        as a elements of KEYSIZE number of lists in a list.
        Same result can be had by splitting the bytes into KEYSIZE
        large chunks, and then transposing the values using numpy
    '''
    splitted_bytes = []
    for i in range(KEYSIZE):
        splitted_bytes.append([])
        for j in range(i, len(cipher_bytes), KEYSIZE):
            splitted_bytes[i].append(cipher_bytes[j])
    return splitted_bytes

def get_score(message: str) -> int:
    '''
    a function that takes input string and using letter 
    frequency it scores it. The higher the score, the better
    '''
    score = 0
    freq = {'a': 0.0812, 'b': 0.0149, 'c': 0.0271, 'd': 0.0432,
    'e': 0.1202, 'f': 0.0230, 'g': 0.0202, 'h': 0.0592, 'i': 0.0731,
    'j': 0.001, 'k': 0.0069, 'l': 0.0398, 'm': 0.0261, 'n': 0.0695,
    'o': 0.0768, 'p': 0.0182, 'q': 0.0011, 'r': 0.0602, 's': 0.0628,
    't': 0.091, 'u': 0.0288, 'v': 0.0111, 'w': 0.0209, 'x': 0.0017,
    'y': 0.0211, 'z': 0.0007, ' ': .13}
    for c in message:
        score += freq.get(c, 0) #if it is not an alphabet, give it a score of 0
    return score/len(message) #normalize the score

def get_key(c_xored_lists: list) -> str:
    '''
        Takes input list of lists of xored values that need cracking
        returns the key string using single character XOR on every list
    '''
    key = ''
    for c_xored_list in c_xored_lists:
        highestscore = 0
        # check for all characters with ascii 0 to 128
        for c in range(0,128):
            #convert the character to an integer to use it in the strxor_c function
            result = xor(bytes(c_xored_list), bytes([c]))
            #decode 'UTF-8' from bytes to string of text
            result = result.decode()
            score = get_score(result)
            if (score > highestscore):
                highestscore = score
                c_candidate = chr(c)
        key += c_candidate
    return(key)

# --------------------------------------------------------
# ------------------- Problem Solution -------------------
# --------------------------------------------------------
# opening the file and reading the ciphertext
def main():
    dirname = os.path.dirname(__file__)
    path = os.path.join(dirname, 'challenge6-text.txt')
    with open(path, 'rb') as f:
        ciphertext = f.read()
    # base64 decode
    ciphertext = b64decode(ciphertext)
    # get smallest hamming distance KEYSIZE
    distances = smallest_hamming_distance(ciphertext)
    # Get keysize from the list of distances
    KEYSIZE = distances[0][0]
    # split the bytes into KEYSIZE lists
    # with chunks of size len(xored)/KEYSIZE
    splitted_bytes = split_bytes(ciphertext, KEYSIZE)
    # use challenge3 code and use the character XOR on every list
    xor_key = get_key(splitted_bytes)
    print('XOR Key:', xor_key)
    # get the plaintext using the rolling_xor func from challenge 5
    plaintext = xor(ciphertext, xor_key.encode()).decode()
    # save it to a file since it's a large wall of text
    savepath = os.path.join(dirname, 'key6.txt')
    with open(savepath, 'w') as f:
        f.write(plaintext)


if __name__ == "__main__":
    main()