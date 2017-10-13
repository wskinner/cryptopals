from util import *
from p52 import IteratedHash
from sys import argv

def find_collision(h, k, blocksize):
    '''
    Find a collision between a single block message and a message of 2^(k-1) blocks
    '''
    if blocksize == 1:
        start = 0
    else:
        start = 2**((blocksize - 1) * 8)
    end = 2**(blocksize * 8)
    dummy_blocks = keygen(2**(k-1))
    dummy_hash = h().update(dummy_blocks)

    print 'Finding collisions between %d and %d' % (start, end)
    for single_block1 in xrange(start, end):
        for single_block2 in xrange(single_block1, end):
            s1 = num_to_str(single_block1, 8 * blocksize)
            s2 = num_to_str(single_block2, 8 * blocksize)
            #print 's1, s2:', s1.encode('hex'), s2.encode('hex')
            h1 = h().update(s1).digest()

            h2 = dummy_hash.clone().update(s2).digest()
            #print 'h1, h2:', h1.encode('hex'), h2.encode('hex')
            if h2 == h1:
                print 'Found collision', s1.encode('hex'), s2.encode('hex'), '->', h1.encode('hex')
                return s1, dummy_hash.state(), s2
    print 'Failed to find a collision'

def find_k_collisions(h, k, blocksize):
    collisions = []
    for i in range(k, 0, -1):
        collisions.append(find_collision(h, i, blocksize))

    return collisions

def attack(h, blocksize, m):
    k = len(m) / blocksize
    collisions = find_k_collisions(h, k, blocksize)
    
    state_to_i = {}
    hasher = h()
    for i, c in enumerate(m):
        hasher.update(c)
        state_to_i[hasher.state] = i

def test_find_k_collisions():
    k = 3
    bs = 2
    h = lambda: IteratedHash(ecb_encrypt)

    collisions = find_k_collisions(h, k, bs)
    print collisions

if __name__ == '__main__':
    msg = argv[1]
    h = lambda: IteratedHash(ecb_encrypt)
    blocksize = 2
    attack(h, blocksize, msg)
