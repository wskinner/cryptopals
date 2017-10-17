from random import SystemRandom
from util import *
from hashlib import sha256
import json

# Default parameters

class DSAParams(object):
    
    P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

    def __init__(self, 
            p=None,
            q=None,
            g=None,
            x=None,
            y=None):
        '''
        p the prime modulus, q the prime divisor of p-1,
        g a generator of a subgroup of order q in the multiplicative group of GF(p), such that 1 < g < p.
        '''
        self.p, self.q, self.g, self.x, self.y = (p, q, g, x, y)

    @classmethod
    def new(cls, g=None):
        '''
        Generate a new set DSA keypair using the default parameters for p, q, g.
        '''
        if g is None:
            g = cls.G
        x, y = DSAParams.keygen(cls.P, cls.Q, g)

        return DSAParams(p=cls.P, q=cls.Q, g=g, x=x, y=y)
    
    @classmethod
    def keygen(cls, p, q, g):
        N = q.bit_length()
        L = p.bit_length()

        assert N % 8 == 0
        rand = SystemRandom()
        c = rand.getrandbits(N + 64)
        x = (c % (q - 1)) + 1
        assert 1 <= x and x <= q - 1

        y = modexp(g, x, p)
        return x, y

    def __str__(self):
        return json.dumps(dict(p=self.p, q=self.q, g=self.g, x=self.x, y=self.y))

class DSA(object):
    '''
    DSA implementation according to http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

    The accepted hash algorithms are specified in 
    FIPS-180 http://ws680.nist.gov/publication/get_pdf.cfm?pub_id=910977
    '''

    def __init__(self, params=None, digest=sha256):
        if params is None:
            params = DSAParams.new()
        self.params = params
        self.digest = digest
        self.rand = SystemRandom()

    @classmethod
    def new(cls):
        params = DSAParams.new()
        return DSA(params)

    def gen_k(self):
        k = self.rand.randint(1, self.params.q - 1)
        return k, invmod(k, self.params.q)

    def leftmost(self, msg):
        '''
        Interpret the leftmost n_bits bits of msg as an integer, and
        return that integer.
        '''
        return str_to_num(msg[:self.zlen()/8])

    def zlen(self):
        N = self.params.q.bit_length()
        outlen = self.digest().digest_size * 8
        return min(N, outlen)

    def sign(self, msg, k=None, k_inv=None):
        r, s = (0, 0)
        while r == 0 or s == 0:
            if k is None:
                k, k_inv = self.gen_k()
            assert (k * k_inv) % self.params.q == 1

            r = modexp(self.params.g, k, self.params.p) % self.params.q

            digester = self.digest()
            digester.update(msg)
            hsh = digester.digest()

            z = self.leftmost(hsh)
            s = (k_inv * (z + self.params.x * r)) % self.params.q
            assert ((s * k - z) * invmod(r, self.params.q)) % self.params.q == (self.params.x * r * invmod(r, self.params.q)) % self.params.q

        return (r, s)

    def validate(self, sig, msg):
        '''
        sig a tuple of (r, s)
        '''
        r, s = sig
        if r <= 0 or r >= self.params.q:
            print 'r out of bounds'
            return False
        if s <= 0 or s >= self.params.q:
            print 's out of bounds'
            return False

        digester = self.digest()
        digester.update(msg)
        hsh = digester.digest()
        z = self.leftmost(hsh)

        w = invmod(s, self.params.q)
        u1 = (z * w) % self.params.q
        u2 = (r * w) % self.params.q

        v1 = modexp(self.params.g, u1, self.params.p)
        v2 = modexp(self.params.y, u2, self.params.p)
        v = ((v1 * v2) % self.params.p) % self.params.q
        return v == r


class CrackDSA(DSA):
    def __init__(self, y, z, q):
        params = DSAParams.new()
        params.y = y
        super(CrackDSA, self).__init__(params, sha1)

        self.z = z
        self.q = q

    @classmethod
    def solve_x(cls, s=None, k=None, z=None, r=None, q=None):
        return ((s * k - z) * invmod(r, q)) % q

    def leftmost(self, msg):
        return self.z

    def sign(self, msg, k, k_inv, x):
        self.params.x = x
        return super(CrackDSA, self).sign(msg, k, k_inv)

    def recover_key_from_nonce(self, msg, k, sig):
        candidate = CrackDSA.solve_x(s=sig[1], k=k, z=self.z, r=sig[0], q=self.q)
        return candidate


def test_num_to_str():
    print 'Testing num to str conversion'
    x = 'hello world'
    assert num_to_str(str_to_num(x), len(x) * 8) == x

    x = 'Cooking MCs like a pound of bacon'
    assert num_to_str(str_to_num(x), len(x) * 8) == x

    x = 'a'
    assert num_to_str(str_to_num(x), len(x) * 8) == x

    x = ''
    assert num_to_str(str_to_num(x), len(x) * 8) == x


def test_signature():
    print 'Testing signature validation'
    msg = "Burning them they ain't quick and nimble"
    signer = DSA.new()
    sig = signer.sign(msg)
    assert signer.validate(sig, msg)

    sig1 = (sig[0], sig[1] + 1)
    assert not signer.validate(sig1, msg)

    assert not signer.validate(sig, msg + ' I go crazy when I hear a cymbal')


if __name__ == '__main__':
    test_num_to_str()
    test_signature()
