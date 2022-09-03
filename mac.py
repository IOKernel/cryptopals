from aes import aes_cbc_encrypt, aes_ecb_decrypt
from padding import pkcs7_pad
from utils import xor, get_blocks
def cbc_mac(msg: bytes, key: bytes, iv: bytes) -> bytes:
    """Return the CBC-MAC of msg using key and iv."""
    # pad message to 16 bytes
    msg = pkcs7_pad(msg, 16)
    # encrypt padded message
    return aes_cbc_encrypt(msg, key, iv)[-16:]

def cbc_mac_hash_forgery(orig_hash: str, forged_msg: bytes, key: bytes, iv: bytes):
    wanted_hashbytes = bytes.fromhex(orig_hash)
    if len(forged_msg) % 16 != 0:
        raise ValueError('forged_msg must be a multiple of 16 bytes')
    dec_last_block = aes_ecb_decrypt(wanted_hashbytes, key)
    forged_pt_last_block = b'\x10' * 16
    ct_prev_block = xor(dec_last_block, forged_pt_last_block)
    enc_last_block_msg = get_blocks(aes_cbc_encrypt(forged_msg, key, iv))[-1]
    dec_prev_block = aes_ecb_decrypt(ct_prev_block, key)
    forged_pt_prev_block = xor(dec_prev_block, enc_last_block_msg)
    forged_msg = forged_msg + forged_pt_prev_block
    forged_hash = cbc_mac(forged_msg, key, iv).hex()
    return forged_hash, forged_msg