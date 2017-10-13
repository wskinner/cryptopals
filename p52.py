from util import *
from itertools import combinations

class IteratedHash(object):

    def __init__(self, c, h='\xff\xff'):
        '''
        h is just 2 bytes of state. c is a function that takes 16 bytes to 16 random
        bytes, e.g. AES. c(msg, key) -> 16 bytes
        '''
        self.h = h
        self.c = c
        self.msg_bytes = []

    def update(self, m):
        for b in m:
            self.msg_bytes.append(b)
            if len(self.msg_bytes) == 16:
                self.h = self.c(''.join(self.msg_bytes), pkcs7_pad(self.h))[:len(self.h)]
                self.msg_bytes = []
        return self
    
    def digest(self):
        if len(self.msg_bytes) != 16:
            st = pkcs7_pad(''.join(self.msg_bytes))
            return self.c(st, pkcs7_pad(self.h))[:len(self.h)]
    
    def clone(self):
        new = IteratedHash(self.c, self.h)
        new.msg_bytes = list(self.msg_bytes)
        return new

    def state(self):
        return self.h, tuple(self.msg_bytes)

def generate_collisions(hash_factory, n):
    '''
    Generate 2^n collisions
    '''
    collisions = []
    hash_to_inputs = {}
    i = 0
    while len(collisions) < 2**n:
        hasher = hash_factory()
        if i < 2**8:
            st = num_to_str(i, 8)
        elif i < 2**16:
            st = num_to_str(i, 16)
        elif i < 2**24:
            st = num_to_str(i, 24)
        elif i < 2**32:
            st = num_to_str(i, 32)
        hsh = hasher.update(st).digest()
        if hsh in hash_to_inputs:
            assert st not in hash_to_inputs[hsh]
            for c in hash_to_inputs[hsh]:
                yield (c, st)
                collisions.append((c, st))
            hash_to_inputs[hsh].add(st)
        else:
            hash_to_inputs[hsh] = set([st])
        i += 1

def double_ecb_encrypt(msg, key):
    k2 = ecb_encrypt(msg, key)
    return ecb_encrypt(k2, key)

if __name__ == '__main__':
    f = lambda : IteratedHash(ecb_encrypt)
    g = lambda : IteratedHash(double_ecb_encrypt, h='\xff\xff')
    
    n = 16
    f_collisions = generate_collisions(f, n)
    i = 0
    for c in f_collisions:
        g1 = g().update(c[0]).digest()
        g2 = g().update(c[1]).digest()
        if g1 == g2:
            print 'Found collision in g after', i, 'iterations!', c, '->', g1
            break
        i += 1
