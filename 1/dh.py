import random
import struct
import hashlib
from util import modexp
class DiffieHellman:
    default_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    # P a prime, g the base, and secret mod p (a secret, of course)
    def __init__(self, p=None, g=None, secret=None, public=None):
        self.p = p
        self.g = g
        self.secret = secret
        self.public = public
       
        if p is None:
            self.p = DiffieHellman.default_p
            self.g = 2
        if secret is None:
            self.secret = random.randint(0, self.p)
        if public is None:
            self.public = modexp(self.g, self.secret, self.p)
            print 'Generating public key', {
                    'g': self.g,
                    'p': self.p,
                    'result': self.public,
                    'secret': self.secret
                    }

    def __str__(self):
        return 'DiffieHellman instance (p=%s, g=%s, secret=%s, public=%s' % (
                self.p, self.g, self.secret, self.public
                )

    def exchange(self, other):
        x = modexp(other.public, self.secret, self.p)

        # There's no better simple way to do this and I'm lazy: https://stackoverflow.com/questions/4358285/is-there-a-faster-way-to-convert-an-arbitrary-large-integer-to-a-big-endian-seque/4358429#4358429
        result = hex(x)[2:]
        print 'Performing DH exchange', {
                'p': self.p,
                'g': self.g,
                'other public': other.public, 
                'my secret': self.secret,
                'shared secret': result
                }
        return result

class Person34:
    def __init__(self, other, name, msg=None):
        self.other = other
        self.name = name
        self.msg = msg

    def make_key(self, secret):
        sha1 = hashlib.sha1()
        sha1.update(secret)
        return sha1.digest()[:16]

    # This person will play the role of A
    def start(self):
        self.dh = DiffieHellman()
        self.other.rcv_msg1(self.dh.p, self.dh.g, self.dh.public)
        
    def rcv_msg1(self, p, g, A):
        self.dh = DiffieHellman(p, g)
        self.other_dh = DiffieHellman(p, g, public=A)
        self.shared_secret = self.dh.exchange(self.other_dh)
        print self.name, 'generated shared secret', self.shared_secret.encode('hex')
        self.key = self.make_key(self.shared_secret)
        self.other.rcv_msg2(self.dh.public)

    def rcv_msg2(self, A):
        self.other_dh = DiffieHellman(self.dh.p, self.dh.g, public=A)
        self.shared_secret = self.dh.exchange(self.other_dh)
        print self.name, 'generated shared secret', self.shared_secret.encode('hex')
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

if __name__ == '__main__':
    test2()

