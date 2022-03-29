#!/usr/bin/env python3
'''
    to run, start the eve server first, then bob then alice.
    then type anything in alice or bob terminals to chat
''' 
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime
from utils import Random
from os import urandom
import threading
import socket

# Connection Data
host = '127.0.0.1'
port = 10000
clientname = 'C'


def gen_srp_vals(email, password):
    # constants
    N = getPrime(512)
    g = 2
    k = 3

    # generate random integer salt
    rng = Random(int.from_bytes(urandom(16), 'big'))
    salt = rng.random()

    # set user/pass
    l = email.decode()
    P = password.decode()

    # hash salt + password
    hash_256 = SHA256.new()
    hash_256.update((str(salt)+P).encode())
    xH = hash_256.hexdigest()

    # convert to int
    x = int(xH, 16)
    v = pow(g, x, N)
    return N, g, k, salt, v

def echo(message, client):
    if type(message) is str:
        message = message.encode()
    print(f"Client: {message.decode()}")
    client.send(message)

def get_creds(client):
    client.send(b'Type your email')
    email = client.recv(1024)
    client.send(b'Type your password')
    password = client.recv(1024)
    return email, password

def handle(client):
    email, password = get_creds(client)
    N, g, k, salt, v = gen_srp_vals(email, password)
    while True:
        try:
            # Broadcasting Messages
            message = client.recv(1024)

            if message == b'':
                shutoff(client)
                break

            echo(message, client)
        
        except:
            shutoff(client)
            break

def shutoff(client):
    # Removing And Closing Clients
    clients.remove(client)
    client.close()
    echo(f'Client left!', client)

# Receiving / Listening Function
def receive():
    while True:
        # Accept Connection
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        # Set Nickname
        clients.append(client)
        
        # Print And Broadcast Nickname
        echo(f"Client joined!".encode(), client)

        # Start Handling Thread For Client
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

# Lists For Clients and Their Nicknames
clients = []
print(f'Starting server at {host}:{port}')
receive()
