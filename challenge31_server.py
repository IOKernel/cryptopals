from http.server import BaseHTTPRequestHandler, HTTPServer
import time
from hashing import sha1
from utils import xor, bitstring_to_bytes
import struct
from urllib.parse import urlparse, parse_qs
hostName = "localhost"
serverPort = 8888
key = b'mangobay'

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def hmac(key: bytes, message: bytes, hash, blockSize: int, outputsize: int) -> str:
    block_sized_key = computeBlockSizedKey(key, hash, blockSize, outputsize)
    o_key_pad = xor(block_sized_key, b'\x5c' * blockSize)   # Outer padded key
    i_key_pad = xor(block_sized_key, b'\x36' * blockSize)   # Inner padded key
    return hash(o_key_pad + in_bytes(hash(i_key_pad + message), outputsize))

def computeBlockSizedKey(key, hash, blockSize, outputsize):
    # Keys longer than blockSize are shortened by hashing them
    if (len(key) > blockSize):
        key = in_bytes(hash(key), outputsize)

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (len(key) < blockSize):
        return key + b'\x00'*(blockSize-len(key))
    return key

def in_bytes(hexstr, outputsize):
    # takes a hex-string and returns bytes representation of it
    # inefficient, there are easier ways
    hexint = int(hexstr, 16)
    hexbin = bin(hexint)[2:].rjust(outputsize*8, '0')
    return bitstring_to_bytes(hexbin)

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            params = parse_qs(urlparse(self.path).query)
            filename = params.get('file')[0].encode()
            given_signature = params.get('signature')[0]
            valid_signature = hmac(key, filename, sha1, 64, 20)
            print(f"{filename = }\n{given_signature = }\n{valid_signature = }")
            valid = self.insecure_compare(given_signature, valid_signature)
            if valid:
                self.send_response(200)
            else:
                self.send_response(500)
            self.send_header('Content-Type', 'text/html' )
            self.end_headers()
        except:
            self.send_response(400)

    def insecure_compare(self, sig_a, sig_b):
        if len(sig_b) != len(sig_a):
            return False
        for byte_index in range(len(sig_a)):
            if sig_a[byte_index] != sig_b[byte_index]:
                return False
            time.sleep(0.01)
        return True


if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")