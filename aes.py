from os import urandom
from Crypto.Cipher import AES
from utils import get_blocks, xor

BLOCKSIZE = 16

def random_bytes_gen(length: int) -> bytes:
    """
        Input: length of bytes to generate
        Output: random bytes of length
    """
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

def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
        Input: plaintext bytes, key bytes
        Output: ciphertext bytes
    """
    # create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
        Input: ciphertext bytes, key bytes
        Output: plaintext bytes
    """
    # create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# AES_CBC_MODE

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
        Input: plaintext bytes, key bytes, iv bytes
        Output: ciphertext bytes
    """
    # Check Intro to Cryptography Chapter 5 for equations
    ciphertext = []
    pt_blocks = get_blocks(plaintext)
    ct_previous = iv
    for block_index, plain_block in enumerate(pt_blocks):        
        plain_xored = xor(plain_block, ct_previous)
        encrypted = aes_ecb_encrypt(plain_xored, key)
        ciphertext.append(encrypted)
        ct_previous = ciphertext[block_index]
    return b''.join(ciphertext)

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
        Input: ciphertext bytes, key bytes, iv bytes
        Output: plaintext bytes
    """
    # Check Intro to Cryptography Chapter 5 for equations
    #! DOES NOT DECRYPT LAST BLOCK WELL, FIX LATER
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
    """
        Input: counter value, blocksize
        Output: bytes of counter value
    """
    counter_hex = hex(counter)[2:]
    if len(counter_hex)%2:
        counter_hex = '0' + counter_hex
    counter_bytes = bytes.fromhex(counter_hex)
    return counter_bytes + bytes(blocksize//2-len(counter_bytes))

def get_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
        Input: key bytes, nonce bytes, length of keystream
        Output: keystream bytes
    """
    keystream = b""
    for i in range(length):
        counter_bytes = nonce + bytes_counter(i)
        keystream += aes_ecb_encrypt(counter_bytes, key)
    return keystream

def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
        Input: plaintext bytes, key bytes, nonce bytes
        Output: ciphertext bytes
    """
    pt_blocks = get_blocks(plaintext)
    keystream_length = len(pt_blocks)
    keystream = get_keystream(key, nonce, keystream_length)
    keystream_blocks = get_blocks(keystream)
    ciphertext = []
    for block, pt_block in enumerate(pt_blocks):
        ct = xor(pt_block, keystream_blocks[block])
        ciphertext.append(ct)
    return b''.join(ciphertext)

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
        Reimplement it allowing input deciding the counter value to allow
        editing of a specific block of cipher
    """
    cipher_blocks = get_blocks(ciphertext)
    keystream_length = len(cipher_blocks)
    keystream = get_keystream(key, nonce, keystream_length)
    plaintext = []
    keystream_blocks = get_blocks(keystream)
    for block, cipher_block in enumerate(cipher_blocks):
        pt = xor(cipher_block, keystream_blocks[block])
        plaintext.append(pt)
    return b''.join(plaintext)