def detect_padding(plaintext: bytes) -> bool:
    padding_len = plaintext[-1]
    padding = plaintext[-padding_len:]
    for i in padding:
        if i != padding_len:
            return False
    return padding_len == len(padding)

def pkcs7_pad(plaintext: bytes, blocksize=16) -> bytes:
    """ 
        Input: plaintext string or bytes, block size wanted
        Output: padded plaintext in bytes
    """
    if type(plaintext) is str:
        plaintext = plaintext.encode()
    # check for if pt is padded already or multiple of blocksize
    # WILL NOT pad if plaintext is multiple of blocksize
    if not len(plaintext)%blocksize:
        padding_state = detect_padding(plaintext)
        if padding_state:
            print('ALREADY PADDED')
            return plaintext
    rem_bytes = blocksize - len(plaintext)%blocksize
    padding = bytes([rem_bytes] * rem_bytes)        
    padded = plaintext + padding
    return padded

def pkcs7_unpad(plaintext: bytes, blocksize: int = 16) -> bytes:
    """ 
        Input: plaintext padded
        Output: unpadded plaintext
    """    
    if not len(plaintext)%blocksize:
        padding_state = detect_padding(plaintext)
        if padding_state:
            padding_len = plaintext[-1]
            return plaintext[:-padding_len]
    raise ValueError('bad padding', plaintext) 