#!/usr/bin/env python3
# server/client modified from https://www.neuralnine.com/tcp-chat-in-python/
'''
    to run, start the eve server first, then bob then alice.
    then type anything in alice or bob terminals to chat
''' 
import threading
import socket
from hashing import sha1
from aes import aes_cbc_decrypt, aes_cbc_encrypt
from padding import pkcs7_pad, pkcs7_unpad
p = 0
shared_key = b''
fake_key = b''

# Connection Data
host = '127.0.0.1'
port = 10000
clientnames = 'AB'

def decrypt(msg, shared_key):
    iv = msg[-16:]
    pt_padded = aes_cbc_decrypt(msg[:-16], shared_key, iv)
    return pkcs7_unpad(pt_padded), iv

def encrypt(msg, shared_key, iv):
    pt_padded = pkcs7_pad(msg)
    ct = aes_cbc_encrypt(pt_padded, shared_key, iv)
    return ct + iv


def relay(message, clientA):
    if type(message) is str:
        message = message.encode()

    for client in clients:
        if clientA != client:
            client.send(message)

def handle(client):
    global p
    global shared_key
    while True:
        try:
            # Broadcasting Messages
            message = client.recv(1024)
            # initiation of dh and encryption
            if message[:8] == b"[p, g] =":
                print("\U00002705 Received DH parameters...")
                msg = message.decode()
                p, g = [n.strip(',') for n in msg.split()[3:]]

                # When g = 1, pow(g,a,p) = 1
                # When g = p, pow(g,a,p) = 0
                # when g = p-1, pow(g,a,p) = 1
                msg = f"[p, g] = {p}, {p}".encode()
                shared_key = sha1('0'.encode()).bytes()[0:16]
                
            # receive other's public key
            elif b'B =' in message:
                print("\U00002705 received public key B")
                msg = message

            elif b'A =' in message:
                print("\U00002705 received public key A")
                msg = "A = " + p
                msg = msg.encode()

            elif message == b"ACK":
                msg = message

            elif message == b'':
                shutoff(client)
                break

            else:
                pt, iv = decrypt(message, shared_key)
                index = clients.index(client)
                nickname = nicknames[index]
                print(f'\033[32m[Decrypted]\033[0m {nickname} -> {nicknames[(index+1)%2]}: {pt.decode()}')
                msg = encrypt(pt, shared_key, iv)
            relay(msg, client)
        
        except:
            shutoff(client)
            break

def shutoff(client):
    # Removing And Closing Clients
    index = clients.index(client)
    clients.remove(client)
    client.close()
    nickname = nicknames[index]
    relay(f'{nickname} left!', client)
    nicknames.remove(nickname)

# Receiving / Listening Function
def receive():
    while True:
        # Accept Connection
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        # Set Nickname
        nickname = clientnames[(len(clients) + 1) % 2]
        nicknames.append(nickname)
        clients.append(client)
        
        # Print And Broadcast Nickname
        print(f"Nickname is {nickname}")
        relay(f"{nickname} joined!".encode(), nickname)

        # Start Handling Thread For Client
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

# Lists For Clients and Their Nicknames
clients = []
nicknames = []
print(f'Starting server at {host}:{port}')
receive()