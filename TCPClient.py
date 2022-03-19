import socket
import threading

class Client():
    def __init__(self, HOST = 'localhost', PORT = 10000):
        # create a TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = HOST
        self.port = PORT

        # connect to the server
        self.connect()

        # Starting Threads For Listening And Writing
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        write_thread = threading.Thread(target=self.write)
        write_thread.start()    
            

    def connect(self):
        try:
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
        except:
            print('server is off')
            
    # Sending Messages To Server
    def write(self):
        while True:
            try:
                message = f"{input('')}"
                self.sock.sendall(message.encode())        
            except KeyboardInterrupt:
                print('closing connection.')
                exit()
    # Listening to Server and Sending Nickname
    def receive(self):
        while True:
            try:
                # Receive Message From Server
                # If 'NICK' Send Nickname
                message = self.sock.recv(1024)
                if message == b'':
                    print("connection lost!")
                    self.sock.close()
                    break    
                print(message.decode())
            except:
                # Close Connection When Error
                print("An error occured!")
                self.sock.close()
                break