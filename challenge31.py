#!/usr/bin/env python3
# Implement and break HMAC-SHA1 with an artificial timing leak
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
                break
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    URL = 'http://localhost:8888/test'
    filename = "flag.txt"
    timer_start = time.time()
    attack(URL, filename, tolerance = 0.005)
    solve_time = time.time() - timer_start
    print(f"solved in {solve_time:.0f} seconds")

if __name__ == "__main__":
    main()