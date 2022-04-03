#!/usr/bin/env python3
'''
    to run, start the eve server first, then bob then alice.
    then type anything in alice or bob terminals to chat
''' 
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.number import getPrime
from utils import Random, power_mod
from time import time
from os import urandom
import threading
import socket
from aes import aes_cbc_decrypt, aes_cbc_encrypt
from padding import pkcs7_pad, pkcs7_unpad

# Connection Data
host = '127.0.0.1'
port = 10000


def gen_srp_vals(email, password):
    # constants
    N = getPrime(512)
    g = 2
    k = 3

    # generate random integer salt
    rng = Random(int.from_bytes(urandom(16), 'big'))
    salt = rng.random()

    P = password

    # hash salt + password
    hash_256 = SHA256.new()
    hash_256.update((str(salt)+P).encode())
    xH = hash_256.hexdigest()

    # convert to int
    x = int(xH, 16)
    v = power_mod(g, x, N)
    return N, g, k, salt, v

def echo(message, client):
    if type(message) is str:
        message = message.encode()
    print(f"Client: {message.decode()}")
    client.send(message)

def decrypt(msg, shared_key):
    iv = msg[-16:]
    pt_padded = aes_cbc_decrypt(msg[:-16], shared_key, iv)
    return pkcs7_unpad(pt_padded), iv

def get_creds(client):
    email, password = client.recv(1024).decode().split(',')
    print(f"Received Email: {email}\nPassword: {password}")
    return email, password

def handle(client):
    # initialization with client
    email, password = get_creds(client)
    # simulate preset user password, code will work only if client uses
    # the same password
    password = "secretpassword"
    # get secure remote password parameters and send them to client
    N, g, k, salt, v = gen_srp_vals(email, password)
    client.send(f"{str(N)},{str(g)},{str(k)}".encode())

    # get client public key
    A = int(client.recv(1024).decode())

    # send salt, and B (B = kv + g**b%N)
    b = Random(int(time())).random()
    b = power_mod(b, 1, N)
    B = k*v + power_mod(g, b, N)
    client.send(f"{salt}, {B}".encode())

    # compute uH and u
    hash_256 = SHA256.new()
    hash_256.update((str(A)+str(B)).encode())
    uH = hash_256.hexdigest()
    # convert to int
    u = int(uH, 16)

    # generate S | S = (A * v**u) ** b % N
    S = power_mod(A*power_mod(v,u,N),b,N)
    print(S)

    # generate K | K = sha256(S)
    hash_256 = SHA256.new()
    hash_256.update((str(S)).encode())
    K = hash_256.hexdigest()
    shared_key = hash_256.digest()
    
    # generate HMAC
    h = HMAC.new(K.encode(), digestmod=SHA256)
    h.update(str(salt).encode())
    hmac_digest = h.hexdigest()

    # verify HMAC and abort if not verified
    client_hmac = client.recv(1024).decode()
    if client_hmac != hmac_digest:
        print("INVALID HMAC, ABORTING")
        client.send(b"INVALID HMAC/PASSWORD")
        client.close()
    else:
        print("VALIDATED.. Starting secure messaging")
    
    while True:
        try:
            # Broadcasting Messages
            message = client.recv(1024)

            if message == b'':
                client.close()
                break

            # decrypt incoming messages using the shared key
            pt, _ = decrypt(message, shared_key)
            print(f'\033[32m[Decrypted]\033[0m C -> {pt.decode()}')
        
        except:
            client.close()
            break

# Receiving / Listening Function
def receive():
    while True:
        # Accept Connection
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        
        # Print And Broadcast Nickname
        echo(f"Client joined!".encode(), client)

        # Start Handling Thread For Client
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen()

print(f'Starting server at {host}:{port}')
receive()
