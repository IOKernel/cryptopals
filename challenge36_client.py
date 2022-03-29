#!/usr/bin/env python3
from utils import power_mod, Random
import socket
import threading

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
            
        except:
            print('server is off')
            
    # Sending Messages To Server
    def write(self):
        while True:
            message = input('')
            try:
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
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a = Random().random()
    client = Client()


if __name__ == "__main__":
    main()