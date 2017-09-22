import random
import struct

def modexp(x, e, m):
    X = x
    E = e
    Y = 1
    while E > 0:
        if E % 2 == 0:
            X = (X * X) % m
            E = E/2
        else:
            Y = (X * Y) % m
            E = E - 1
    return Y

class DiffieHellman:
    # P a prime, g the base, and secret mod p (a secret, of course)
    def __init__(self, p=None, g=None, secret=None, public=None):
        self.p = p
        self.g = g
        self.secret = secret
        self.public = public
       
        if p is None:
            self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
            self.g = 2
        if secret is None:
            self.secret = random.randint(0, self.p)
        if public is None:
            self.public = modexp(self.g, self.secret, self.p)

    def exchange(self, other):
        x = modexp(other.public, self.secret, self.p)
        # There's no better simple way to do this and I'm lazy: https://stackoverflow.com/questions/4358285/is-there-a-faster-way-to-convert-an-arbitrary-large-integer-to-a-big-endian-seque/4358429#4358429
        return hex(x)[2:]

def test():
    alice = DiffieHellman(37, 5, random.randint(0, 37))
    bob = DiffieHellman(37, 5, random.randint(0, 37))

    assert alice.exchange(bob) == bob.exchange(alice)

def test2():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    alice = DiffieHellman(p, g, random.randint(0, p))
    bob = DiffieHellman(p, g, random.randint(0, p))

    assert alice.exchange(bob) == bob.exchange(alice)
    
test2()

