#!/usr/bin/env python3
from TCPClient import Client
from utils import power_mod, Random

# --------------------------------------------------------
# ---------------------- functions -----------------------
# --------------------------------------------------------
def send_dh(client, p, g, a):
    client.p = p
    client.g = g
    client._private_key = power_mod(a, 1, p)
    client.public_key = power_mod(g, a, p)
    init_str = f"[p, g] = {str(p)}, {str(g)}".encode()
    print(f"{init_str = }")
    print("\U00002705 Sending DH parameters...")
    client.sock.sendall(init_str)
# --------------------------------------------------------
# ------------------------- main -------------------------
# --------------------------------------------------------

def main():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a = Random().random()
    client = Client()
    send_dh(client, p, g, a)


if __name__ == "__main__":
    main()