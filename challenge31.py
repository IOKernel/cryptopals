#!/usr/bin/env python3
import requests
from string import ascii_lowercase, digits
char_space = ascii_lowercase + digits
import time
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def attack(URL, filename, tolerance = 0.01):
    signature = ""
    start_time = time.time()
    requests.get(url = URL, params={'file':filename, 'signature': signature + 'a'})
    end_time = time.time()
    last_time = end_time - start_time
    while True:
        for c in char_space:
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
            
            print(f"Attempting: {payload}")
            # break if status code 200
            if r.status_code == 200:
                print(f"Found signature! : {signature}")
                return payload

            # time tolerance in seconds
            if execution_time > last_time + tolerance:
                signature += c
                print(f"{signature = }")
                last_time = execution_time
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    URL = 'http://localhost:8888/test'
    filename = "flag.txt"
    attack(URL, filename, tolerance = 0.005)

if __name__ == "__main__":
    main()