#!/usr/bin/env python3
from fastapi import FastAPI
import re
from aes import aes_cbc_encrypt
from padding import pkcs7_unpad, detect_padding, pkcs7_pad

KEY = b'YELLOW SUBMARINE'
IV = b'\x00'*16
app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/transfer")
def transfer(hexm: str):
    msg = bytes.fromhex(hexm)
    MAC = msg[-16:]
    MSG = msg[:-16]
    if not detect_padding(MSG):
        MSG = pkcs7_pad(MSG)
    if verify(MSG, IV, MAC):
        MSG = pkcs7_unpad(MSG)
        MSG = MSG.decode()
        from_user = re.search('from=#(\w+)', MSG).group(1)
        # transactions are in the form of to:amount;to:amount*
        transactions = re.search('tx_list=#(.+)', MSG).group(1)
        transactions = transactions.split(';')
        json_transactions = []
        for transaction in transactions:
            to, amount = transaction.split(':')
            json_transactions.append({'to': to, 'amount': amount})
        return {
            "status": "success",
            "from": from_user,
            "transactions": json_transactions,
            }
    else:
        return {"status": "error"}

def verify(MSG, IV, MAC):
    key = KEY
    return aes_cbc_encrypt(MSG, key, IV)[-16:] == MAC