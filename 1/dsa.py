from random import SystemRandom
from util import *
from hashlib import sha256

import bitarray

# Default parameters
P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def str_to_num(st):
    ba = bitarray.bitarray()
    ba.frombytes(st)
    total = 0
    n = len(st) * 8 - 1
    for b in ba:
        if b: total += 2**n
        n -= 1
    
    return total

def num_to_str(num, n_bits):
    if num == 0: 
        return ''
    n_bits = max(n_bits, 8)
    mask = 0xff << n_bits - 8
    chars = []
    shift_bits = n_bits - 8
    while mask >= 0xff:
        b = (num & mask) >> shift_bits
        chars.append(chr(b))
        mask = mask >> 8
        shift_bits -= 8

    return ''.join(chars)

class DSAParams:
    
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

    @staticmethod
    def new():
        '''
        Generate a new set DSA keypair using the default parameters for p, q, g.
        '''
        rand = SystemRandom()
        x = rand.randint(1, Q)
        y = modexp(G, x, P)

        return DSAParams(p=P, q=Q, g=G, x=x, y=y)

class DSA:
    '''
    DSA implementation according to http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

    The accepted hash algorithms are specified in 
    FIPS-180 http://ws680.nist.gov/publication/get_pdf.cfm?pub_id=910977
    '''

    def __init__(self, params, digest=sha256):
        self.params = params
        self.digest = digest
        self.rand = SystemRandom()

    @staticmethod
    def new():
        params = DSAParams.new()
        return DSA(params)

    def gen_k(self):
        k = self.rand.randint(1, self.params.q - 1)
        return k, invmod(k, self.params.q)

    def leftmost(self, msg, n_bits):
        '''
        Interpret the leftmost n_bits bits of msg as an integer, and
        return that integer.
        '''
        return str_to_num(msg[:n_bits/8])

    def zlen(self):
        N = self.params.q.bit_length()
        outlen = self.digest().digest_size * 8
        return min(N, outlen)

    def sign(self, msg):
        r, s = (0, 0)
        while r == 0 or s == 0:
            digester = self.digest()
            k, k_inv = self.gen_k()
            r = modexp(self.params.g, k, self.params.q)
            zlen = self.zlen()

            digester.update(msg)
            hsh = digester.digest()
            print 'hsh', hsh.encode('hex')

            z = self.leftmost(hsh, zlen)
            print 'z', z
            s = (k_inv * (z + self.params.x * r)) % self.params.q
        
        print r, s
        return (r, s)

    def validate(self, sig, msg):
        '''
        sig a tuple of (r, s)
        '''
        r, s = sig
        if r <= 0 or r >= self.params.q:
            return False
        if s <= 0 or s >= self.params.q:
            return False

        digester = self.digest()
        digester.update(msg)
        hsh = digester.digest()
        print 'hsh', hsh.encode('hex')

        w = invmod(s, self.params.q)
        z = self.leftmost(hsh, self.zlen())
        print 'z', z
        u1 = (z * w) % self.params.q
        u2 = (r * w) % self.params.q
        v = ((modexp(self.params.g, u1, self.params.p) *
                modexp(self.params.y, u2, self.params.p)) % self.params.p) % self.params.q
        print 'v', v
        return v == r

def test_num_to_str():
    x = 'hello world'
    assert num_to_str(str_to_num(x), len(x) * 8) == x

    x = 'Cooking MCs like a pound of bacon'
    assert num_to_str(str_to_num(x), len(x) * 8) == x

    x = 'a'
    assert num_to_str(str_to_num(x), len(x) * 8) == x

    x = ''
    assert num_to_str(str_to_num(x), len(x) * 8) == x

def test_signature():
    msg = "Burning them they ain't quick and nimble"
    signer = DSA.new()
    sig = signer.sign(msg)
    assert signer.validate(sig, msg)

test_num_to_str()
test_signature()
