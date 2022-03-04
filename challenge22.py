#!/usr/bin/env python3
import time
from utils import ans_check, Random
# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def wait(seconds: int):
    timer_rand = Random()
    if type(seconds) is float:
        seconds = int(seconds)
    sleep_time = timer_rand.random()/(2**32)*seconds 
    time.sleep(sleep_time)

def find_seed(rand_output) -> int:
    current_time = int(time.time())
    while True:
        rand_guess = Random(current_time)
        rng_guess = rand_guess.random()
        if rng_guess == rand_output:
            return current_time    
        current_time -= 1
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------
def main():
    print('starting program')
    wait(100)
    seed = int(time.time())
    rand = Random(seed)
    rng = rand.random()
    print(f'{rng = }\n{seed = }')
    wait(100)
    extracted_seed = find_seed(rng)
    print(f'Extracted seed: {extracted_seed}')
    ans_check(seed, extracted_seed)

if __name__ == "__main__":
    main()