from util import *
from dh import DiffieHellman
import hashlib

class Person:
    def __init__(self, other, name, msg=None):
        self.other = other
        self.name = name
        self.msg = msg

    def make_key(self, secret):
        sha1 = hashlib.sha1()
        sha1.update(self.shared_secret)
        return sha1.digest()[:16]

    # This person will play the role of A
    def start(self):
        self.dh = DiffieHellman()
        self.other.rcv_msg1(self.dh.p, self.dh.g, self.dh.public)
        
    def rcv_msg1(self, p, g, A):
        self.dh = DiffieHellman(p, g)
        self.other_dh = DiffieHellman(p, g, public=A)
        self.shared_secret = self.dh.exchange(self.other_dh)
        self.key = self.make_key(self.shared_secret)
        self.other.rcv_msg2(self.dh.public)

    def rcv_msg2(self, A):
        self.other_dh = DiffieHellman(self.dh.p, self.dh.g, public=A)
        self.shared_secret = self.dh.exchange(self.other_dh)
        self.key = self.make_key(self.shared_secret)
        iv = keygen()
        print self.name, 'sending', self.msg
        enc = cbc_encrypt(self.msg, self.key, iv)
        self.other.rcv_msg3(enc + iv)

    def rcv_msg3(self, enc_iv):
        rec_iv = enc_iv[-16:]
        rec_enc = enc_iv[:-16]
        rec_msg = cbc_decrypt(rec_enc, self.key, rec_iv)
        print self.name, 'received', rec_msg
        
        iv = keygen()
        enc = cbc_encrypt(rec_msg, self.key, iv)
        print self.name, 'sending', rec_msg
        self.other.rcv_msg4(enc + iv)

    def rcv_msg4(self, enc_iv):
        iv = enc_iv[-16:]
        enc = enc_iv[:-16]
        msg = cbc_decrypt(enc, self.key, iv)
        print self.name, 'received', msg

alice = Person(None, 'Alice', "Alice's message")
bob = Person(alice, 'Bob', "Bob's message")
alice.other = bob
alice.start()
