#!/usr/bin/env python3
# Break HMAC-SHA1 with a slightly less artificial timing leak
import requests
import time
hexdigits = '0123456789abcdef'
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def attack(URL, filename, tolerance = 0.01):
    signature = ""
    start_time = time.time()
    requests.get(url = URL, params={'file':filename, 'signature': signature + 'a'})
    end_time = time.time()
    last_time = end_time - start_time
    counter = 0
    while True:
        for c in hexdigits:
            # create new signature
            payload = signature + c + (40-1-len(signature))*'_'
            PARAMS = {
                'file': filename,
                'signature': payload
            }
            # time attack
            start_time = time.time()
            r = requests.get(url = URL, params=PARAMS)
            end_time = time.time()
            execution_time = end_time - start_time
            if counter > len(hexdigits)*3:
                signature = signature[:-1]
                counter = 0
                last_time = execution_time - tolerance
            print(f"Attempting: {payload}")
            counter += 1
            # break if status code 200
            if r.status_code == 200:
                print(f"Found signature! : {signature}")
                return payload

            # time tolerance in seconds
            if execution_time > last_time + tolerance:
                counter = 0
                signature += c
                print(f"{signature = }")
                last_time = execution_time
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    URL = 'http://localhost:8888/test'
    filename = "flag.txt"
    attack(URL, filename, tolerance = 0.0025)

if __name__ == "__main__":
    main()