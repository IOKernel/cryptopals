from Crypto.Cipher import AES
from os import urandom
from utils import get_blocks, xor
from padding import detect_padding

BLOCKSIZE = 16

def random_bytes_gen(length: int) -> bytes:
    return urandom(length)

# AES_ECB_MODE

def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    """ 
        Input: Ciphertext bytes or hexed string
        Output: True if ciphertext has a repeating block
                False if ciphertext has no repeating block
    """

    blocks = []
    blocks_count = len(ciphertext)//block_size
    for i in range(blocks_count):
        # split ciphertext in blocks of block_size. 16 for AES
        current_block = ciphertext[i*block_size:(i+1)*block_size]
        if current_block in blocks:
            return True
        else:
            blocks.append(current_block)
    return False

def aes_ecb_encrypt(plaintext: bytes, key: bytes, MODE = 'ECB') -> bytes:
    # create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    # create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# AES_CBC_MODE

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    # Check Intro to Cryptography Chapter 5 for equations
    BLOCKSIZE = 16
    ciphertext = []
    pt_blocks = get_blocks(plaintext)
    ct_previous = iv
    for block_index, plain_block in enumerate(pt_blocks):        
        plain_xored = xor(plain_block, ct_previous)
        encrypted = aes_ecb_encrypt(plain_xored, key, 'CBC')
        ciphertext.append(encrypted)
        ct_previous = ciphertext[block_index]
    return b''.join(ciphertext)

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # Check Intro to Cryptography Chapter 5 for equations
    #! DOES NOT DECRYPT LAST BLOCK WELL, FIX LATER
    BLOCKSIZE = 16
    plaintext = []
    ct_blocks = get_blocks(ciphertext)
    ct_blocks.insert(0, iv)
    for block_index, cipher_block in enumerate(ct_blocks[1:]):
        ct_previous = ct_blocks[block_index]
        decrypted = aes_ecb_decrypt(cipher_block, key)
        pt = xor(decrypted, ct_previous)
        plaintext.append(pt)
    return b''.join(plaintext)


# AES_CTR_MODE

def bytes_counter(counter: int = 0, blocksize: int = 16) -> bytes:
    counter = hex(counter)[2:]
    if len(counter)%2:
        counter = '0' + counter
    counter_bytes = bytes.fromhex(counter)
    return counter_bytes + bytes(blocksize//2-len(counter_bytes))

def get_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    keystream = []
    for i in range(length):
        counter_bytes = nonce + bytes_counter(i)
        ks = aes_ecb_encrypt(counter_bytes, key)
        keystream.append(ks)
    return keystream

def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    pt_blocks = get_blocks(plaintext)
    keystream_length = len(pt_blocks)
    keystream = get_keystream(key, nonce, keystream_length)
    ciphertext = []
    for block, cipher_block in enumerate(pt_blocks):
        ct = xor(cipher_block, keystream[block])
        ciphertext.append(ct)
    return b''.join(ciphertext)

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher_blocks = get_blocks(ciphertext)
    keystream_length = len(cipher_blocks)
    keystream = get_keystream(key, nonce, keystream_length)
    plaintext = []
    for block, cipher_block in enumerate(cipher_blocks):
        pt = xor(cipher_block, keystream[block])
        plaintext.append(pt)
    return b''.join(plaintext)