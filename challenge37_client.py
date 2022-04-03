#!/usr/bin/env python3
from utils import power_mod, Random
import socket
import threading
from time import time
from Crypto.Hash import SHA256, HMAC
from aes import aes_cbc_decrypt, aes_cbc_encrypt
from padding import pkcs7_pad, pkcs7_unpad
from os import urandom
'''
    sending A = 0 or A = N forces  S  on the server side to be equal to 0.
    So by setting S = 0 on the client side as well, we bypass password authentication
'''
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------

class Client():
    def __init__(self, HOST = 'localhost', PORT = 10000):
        # create a TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = HOST
        self.port = PORT
        self.other = "S" # other user's nickname
        self.email = "test@test.com"
        self.password = "secretpasswodrd"

        # connect to the server
        self._connect()

        # Starting Threads For Listening And Writing
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        write_thread = threading.Thread(target=self.write)
        write_thread.start()    
            

    def _connect(self):
        # initiate server connection
        try:
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            # sending email (l) and password (P)
            self.sock.sendall(f'{self.email},{self.password}'.encode())

            message = self.sock.recv(1024)
            # receiving N, g, k
            message = self.sock.recv(1024)
            self.N, self.g, self.k = [int(x) for x in message.decode().split(',')]
            
            # sending A the public key in DH
            self.a = Random(int(time())).random()
            self._private_key = power_mod(self.a, 1, self.N)

            #self.A = power_mod(self.g, self._private_key, self.N)

            # sending A = 0, must change S = 0 on client side as well
            self.A = 0
            # sending A = N
            self.A = self.N
            self.sock.send(str(self.A).encode())
            

            # receive salt, B
            message = self.sock.recv(1024)
            self.salt, self.B = [int(x) for x in message.decode().split(',')]

            # compute uH and u
            hash_256 = SHA256.new()
            hash_256.update((str(self.A)+str(self.B)).encode())
            uH = hash_256.hexdigest()
            # convert to int
            self.u = int(uH, 16)

            # get xH and x, hash salt + password
            hash_256 = SHA256.new()
            hash_256.update((str(self.salt)+self.password).encode())
            xH = hash_256.hexdigest()
            # convert to int
            self.x = int(xH, 16)

            # generate S
            var_1 = self.B - self.k*power_mod(self.g, self.x, self.N)
            var_2 = self._private_key + self.u*self.x
            if self.A == 0 or self.A == self.N:
                self.S = 0
            else:
                self.S = power_mod(var_1, var_2, self.N)

            # generate K
            hash_256 = SHA256.new()
            hash_256.update((str(self.S).encode()))
            self.K = hash_256.hexdigest()
            self.shared_key = hash_256.digest()

            # generate HMAC
            h = HMAC.new(self.K.encode(), digestmod=SHA256)
            h.update(str(self.salt).encode())
            hmac_digest = h.hexdigest()
            self.sock.send(hmac_digest.encode())

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
                    print(f"sending ({message}) -> {encrypted_msg}")
                    self.sock.send(encrypted_msg + iv)

                else:
                    self.sock.send(message.encode())

            except KeyboardInterrupt:
                print('closing connection.')
                exit()

    # Listening to Server
    def receive(self):
        while True:
            # Receive Message From Server
            message = self.sock.recv(1024)
                
            # if connection closes
            if message == b'':
                print("connection lost!")
                self.sock.close()
                break

            else:
                print(f"{self.other}: {message.decode()}")
    
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    client = Client()


if __name__ == "__main__":
    main()