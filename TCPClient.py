import socket
import threading
from utils import power_mod, Random
from time import time
from hashing import sha1
from os import urandom
from aes import aes_cbc_decrypt, aes_cbc_encrypt
from padding import pkcs7_pad, pkcs7_unpad

class Client():
    def __init__(self, HOST = 'localhost', PORT = 10000):
        # create a TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = HOST
        self.port = PORT
        # initializing needed parameters
        self._private_key = 0 # private key a|b
        self.public_key = 0 # public key A|B
        self.shared_key = b"" # share key from sha1(s)
        self.other = "" # other user's nickname

        # connect to the server
        self._connect()

        # Starting Threads For Listening And Writing
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        write_thread = threading.Thread(target=self.write)
        write_thread.start()    
            
    def initiate_dh(self, p, g, a):
        # setting DH parameters from user and sending them
        self.p = p
        self.g = g
        self._private_key = power_mod(a, 1, p)
        self.public_key = power_mod(g, self._private_key, p)
        init_str = f"[p, g, A] = {str(p)}, {str(g)}, {str(self.public_key)}".encode()
        print("\U00002705 Sending DH parameters...")
        self.sock.sendall(init_str)

    def _connect(self):
        # initiate server connection
        try:
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
        except:
            print('server is off')
            
    # Sending Messages To Server
    def write(self):
        while True:
            message = input('')
            try:
                if self.shared_key:
                # dh exchange is over, encrypt messages
                    iv = urandom(16)
                    padded = pkcs7_pad(message)
                    encrypted_msg = aes_cbc_encrypt(padded, self.shared_key, iv)
                    self.sock.sendall(encrypted_msg + iv)

                else:
                    self.sock.send(message.encode())

            except KeyboardInterrupt:
                print('closing connection.')
                exit()

    # Listening to Server and Sending Nickname
    def receive(self):
        while True:
            # Receive Message From Server
            message = self.sock.recv(1024)

            # initiation of dh and encryption
            if message[:11] ==  b"[p, g, A] =":
                print("\U00002705 Received DH parameters, sending public key...")
                msg = message.decode()
                self.p, self.g, A = [int(n.strip(',')) for n in msg.split()[4:]]
                b = Random(int(time())).random()
                self._private_key = power_mod(b, 1, self.p)
                self.public_key = power_mod(self.g, self._private_key, self.p)
                s = power_mod(A, self._private_key, self.p)
                self.shared_key = sha1(str(s).encode()).bytes()[0:16]
                print("\U00002705 Connection is now encrypted.")
                self.sock.sendall(f"B = {str(self.public_key)}".encode())

            # receive other's public key
            elif message[:3] == b"B =":
                print("\U00002705 Received public key!")
                B = int(message.split()[2])
                s = power_mod(B, self._private_key, self.p)
                self.shared_key = sha1(str(s).encode()).bytes()[0:16]
                print("\U00002705 Connection is now encrypted.")

            # print join statement and get other's Nicknname
            elif message[2:6] == b"join":
                if not self.other:
                    self.other = message.decode()[0]
                print(message.decode())

            # if connection closes
            elif message == b'':
                print("connection lost!")
                self.sock.close()
                break

            # After key exchange is done, messages are encrypted using the shared key
            # decrypt the message using the iv appended to the text and shared key
            else:
                iv = message[-16:]
                pt_padded = aes_cbc_decrypt(message[:-16], self.shared_key, iv)
                pt = pkcs7_unpad(pt_padded)
                print(f"{self.other}: {pt.decode()}")