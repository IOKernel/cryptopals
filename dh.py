from hashing import sha1
from utils import power_mod
class dh():
    def __init__(self, a):
        # Diffie-Hellman
        self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        self.g = 2
        self._private_a = power_mod(a, 1, self.p)
    
    def gen_public_key(self):
        return power_mod(self.g, self._private_a, self.p)

    def _gen_shared_key(self, bob_key):
        return power_mod(bob_key, self._private_a, self.p)

    def get_key(self, bob_key):
        shared_key = self._gen_shared_key(bob_key)
        shared_key_bytes = str(shared_key).encode()
        return sha1(shared_key_bytes).bytes()