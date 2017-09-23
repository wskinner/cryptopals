from dh import Person34, DiffieHellman
from util import *

class Person35(Person34):
    def start(self):
        print self.name, 'Starting experiment'
        self.dh = DiffieHellman()
        self.other.rcv_msg1(self.dh.p, self.dh.g)

    def rcv_msg1(self, p, g):
        self.dh = DiffieHellman(p=p, g=g)
        self.other_dh = DiffieHellman(p=p, g=g)
        self.other.rcv_msg2('ACK')

    def rcv_msg2(self, msg):
        assert msg == 'ACK'
        self.other.rcv_msg3(self.dh.public)

    def rcv_msg3(self, A):
        self.other_dh.public = A
        print self.name, 'generating shared secret'
        self.shared_secret = self.dh.exchange(self.other_dh)
        self.key = self.make_key(self.shared_secret)
        self.other.rcv_msg4(self.dh.public)
    
    def rcv_msg4(self, B):
        self.other_dh = DiffieHellman(p=self.dh.p, g=self.dh.g, public=B)
        print self.name, 'generating shared secret'
        self.shared_secret = self.dh.exchange(self.other_dh)
        self.key = self.make_key(self.shared_secret)
        iv = keygen()
        enc_iv = cbc_encrypt(self.msg, self.key, iv) + iv
        print self.name, 'sending', self.msg
        self.other.rcv_msg5(enc_iv)

    def rcv_msg5(self, enc_iv):
        rec_iv = enc_iv[-16:]
        rec_enc = enc_iv[:-16]
        rec_msg = cbc_decrypt(rec_enc, self.key, rec_iv)
        print self.name, 'received', rec_msg

        iv = keygen()
        enc = cbc_encrypt(rec_msg, self.key, iv)
        print self.name, 'sending', rec_msg
        self.other.rcv_msg6(enc + iv)

    def rcv_msg6(self, enc_iv):
        iv = enc_iv[-16:]
        enc = enc_iv[:-16]
        msg = cbc_decrypt(enc, self.key, iv)
        print self.name, 'received', msg

class MITM(Person35):
    # Secret is the shared secret that both parties will derive using our 
    # injected g parameter.
    def __init__(self, name, alice=None, bob=None, g=None, A=None, secret=None):
        self.name = name
        self.alice = alice
        self.bob = bob
        self.g = g
        self.A = A
        self.key = self.make_key(secret)
    
    def rcv_msg1(self, p, g):
        self.bob.rcv_msg1(p, self.g)

    def rcv_msg2(self, msg):
        self.alice.rcv_msg2(msg)

    def rcv_msg3(self, A):
        self.bob.rcv_msg3(self.A)

    def rcv_msg4(self, B):
        print 'B', B
        self.alice.rcv_msg4(B)

    def rcv_msg5(self, enc_iv):
        rec_iv = enc_iv[-16:]
        rec_enc = enc_iv[:-16]
        rec_msg = cbc_decrypt(rec_enc, self.key, rec_iv)

        print self.name, 'proxying encrypted message', rec_msg
        self.bob.rcv_msg5(enc_iv)

    def rcv_msg6(self, enc_iv):
        rec_iv = enc_iv[-16:]
        rec_enc = enc_iv[:-16]
        rec_msg = cbc_decrypt(rec_enc, self.key, rec_iv)

        print self.name, 'proxying encrypted message', rec_msg
        self.alice.rcv_msg6(enc_iv)


# If ag is the g Alice chose, and we set g = 1, then
# Alice computes:
# A = ag**a % p == something large
#
# Bob computes:
# B = 1**b % p == 1
# secret = A**b % p
# 
# Alice computes:
# secret = B**a % p == 1
#
# Alice and bob don't have the same secret keys, and can't decrypt each other's
# messages. But Mallory can read Alice's messages to Bob.
# We can fix this by injecting A so that they generate the same secret. Set A=1
def attack1():
    print 'RUNNING ATTACK 1 (g=1, A=1)'
    alice = Person35(None, 'Alice', "Alice's message")
    bob = Person35(None, 'Bob', "Bob's message")
    mallory = MITM('Mallory', alice, bob, g=1, A=1, secret='1L')
    alice.other = mallory
    bob.other = mallory
    alice.start()

# If ag is the g Alice chose, and we set g == p, then
# Bob computes the shared secret as A**b % p == something large
# Bob computes his public key as g**b % p == p**b % p === 0
# Alice computes the shared secret as 0**a % p === 0
#
# To make Bob compute the same secret as Alice, inject A = 0
def attack2():
    print 'RUNNING ATTACK 2 (g=p, A=0)'
    alice = Person35(None, 'Alice', "Alice's message")
    bob = Person35(None, 'Bob', "Bob's message")
    mallory = MITM('Mallory', alice, bob, g=DiffieHellman.default_p, A=0, secret='0L')
    alice.other = mallory
    bob.other = mallory
    alice.start()

# If we choose g = p - 1, then
# Bob's public key B will be either 1 or p-1 depending on whether Bob's secret b
# is even or odd. 
# 1. If b is even, then B can be expressed as K*(p-1)**2 mod p for some
# K. (p-1)**2 = p**2 -2p + 1 === 1 mod p. Therefore by the multiplication rule of 
# modular arithmetic, B == 1 mod p.
# 2. If b is odd, then B can be expressed as K*(p-1)**2 * (p-1). So by the multiplication rule,
# B == p -1 mod p.
# Bob computes the shared secret as A**b % (p)
# Bob computes his public key as (p-1)**b % p (1 or p-1)
# Alice computes the shared secret as B**a % p == ((p-1)**b % p)**a % p
# If B == 1, this is 1**a % p == 1.
# If B == p-1, this is (p-1)**a % p, so it is 1 or p-1 depending on alice's secret.
#
# If we decide to force a secret of 1, then we will inject:
# g = p - 1
# A = 1
# Bob computes:
# secret = 1**b % p == 1
# B = 1 or p-1 
def attack3():
    print 'RUNNING ATTACK 3 (g=p-1, A=1)'
    alice = Person35(None, 'Alice', "Alice's message")
    bob = Person35(None, 'Bob', "Bob's message")
    mallory = MITM('Mallory', alice, bob, g=DiffieHellman.default_p-1, A=1, secret='1L')
    alice.other = mallory
    bob.other = mallory
    alice.start()

def test1():
    alice = Person35(None, 'Alice', "Alice's message")
    bob = Person35(alice, 'Bob', "Bob's message")
    alice.other = bob
    alice.start()

if __name__ == '__main__':
    #test1()
    attack1()
    print '\n\n'
    attack2()
    print '\n\n'
    attack3()
