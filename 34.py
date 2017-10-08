from util import *
from dh import DiffieHellman, Person34
import hashlib

# Normally, Diffie-Hellman works because (g ** a % p) ** b === (g ** b % p) ** a
# and computing log (g ** a  % p ) is hard. But now Mallory sets the public key 
# to P. Obviously p % p === p.
class MITM(Person34):
    def __init__(self, name, alice=None, bob=None):
        self.name = name
        self.alice = alice
        self.bob = bob
        self.key = self.make_key('0L')
    
    # From alice
    def rcv_msg1(self, p, g, A):
        # g ** a % p
        self.alice_pub = A
        self.p = p
        self.bob.rcv_msg1(p, g, p)

    def rcv_msg2(self, A):
        # Bob thinks he computed A**b % p === (g**a % p)**b % p, but he actually computed
        # (p % p)**b % p === p**b % p === 0.
        # Alice thought she computed B**a % p === (g**b % p)**a % p, but she actually computed
        # p**a % p === 0
        self.bob_pub = A
        self.alice.rcv_msg2(self.p)

    def rcv_msg3(self, enc_iv):
        rec_iv = enc_iv[-16:]
        rec_enc = enc_iv[:-16]
        rec_msg = cbc_decrypt(rec_enc, self.key, rec_iv)
        print self.name, 'received', rec_msg
        
        self.bob.rcv_msg3(enc_iv)

    def rcv_msg4(self, enc_iv):
        rec_iv = enc_iv[-16:]
        rec_enc = enc_iv[:-16]
        rec_msg = cbc_decrypt(rec_enc, self.key, rec_iv)
        print self.name, 'received', rec_msg

        self.alice.rcv_msg4(enc_iv)

def test1():
    alice = Person(None, 'Alice', "Alice's message")
    bob = Person(alice, 'Bob', "Bob's message")
    alice.other = bob
    alice.start()

def test2():
    mallory = MITM('Mallory')
    alice = Person(mallory, 'Alice', "Alice's message")
    bob = Person(mallory, 'Bob', "Bob's message")
    mallory.alice = alice
    mallory.bob = bob
    alice.start()

if __name__ == '__main__':
    test2()
