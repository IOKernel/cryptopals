#!/usr/bin/env python3
# server/client modified from https://www.neuralnine.com/tcp-chat-in-python/
import threading
import socket



# Connection Data
host = '127.0.0.1'
port = 10000
clientnames = 'ABCDEF'



def relay(message, clientA):
    if type(message) is str:
        message = message.encode()

    for client in clients:
        if clientA != client:
            client.send(message)

def handle(client):
    while True:
        try:
            # Broadcasting Messages
            message = client.recv(1024)
            if message == b'':
                shutoff(client)
                break
            index = clients.index(client)
            nickname = nicknames[index]
            print(f'{nickname}: {message.decode()}')
            relay(message, client)
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
        nickname = clientnames[len(clients)]
        nicknames.append(nickname)
        clients.append(client)
        

        # Print And Broadcast Nickname
        print(f"Nickname is {nickname}")
        relay(f"{nickname} joined!".encode(), nickname)
        client.sendall('Connected to server!'.encode())

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