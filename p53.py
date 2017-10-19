from p52 import AESHash
from util import single_block_collision, Serializable
from sys import argv
import math
import pickle

class ExpandableMessage(Serializable):

    def __init__(self, hash_factory, k):
        self.hash_factory = hash_factory
        self.max_k = k
        self.collisions = []

    def find_collision(self, initial_state, k):
        '''
        Find a collision between a single block message and a message of 2^(k-1) + 1 blocks
        '''
        print 'find_collision(%s, %d)' % (initial_state.encode('hex'), k)
        # The block size in bytes
        blocksize = self.hash_factory().bs
        dummy_hash = self.hash_factory(h=initial_state)
        dummy_bytes = (blocksize * 2**(k-1)) * '\x00'
        dummy_hash.update(dummy_bytes)

        collision = single_block_collision(self.hash_factory, initial_state,
                dummy_hash.state(),
                blocksize)
        collision['dummy_bytes'] = dummy_bytes
        collision['initial_state'] = initial_state
        print 'Found collision from initial state = "%s"' % initial_state.encode('hex'), collision['s1'].encode('hex'), collision['s2'].encode('hex'), '->', collision['final_state'].encode('hex')

        return collision
    
    def create_message(self, length):
        '''
        Construct a string of length length that hashes to the final state of the
        expandable message.
        '''
        assert self.max_k <= length <= self.max_k + 2**self.max_k - 1
        bitstring = bin(length - self.max_k)[2:]
        while len(bitstring) < self.max_k:
            bitstring = '0' + bitstring
        print 'Paddded bitstring', bitstring
        assert int(bitstring, 2) + self.max_k == length
        prefix = ''
        i = 0
        for bit in bitstring:
            c = self.collisions[i]
            if bit == '0':
                prefix += c['s1']
            else:
                prefix += c['dummy_bytes']
                prefix += c['s2']
            #assert self.hash_factory().update(prefix).digest() == c['final_state']
            i += 1
        
        return prefix

    def build(self):
        initial_state = '\xff\xff'
        for k in range(self.max_k, 0, -1):
            collision = self.find_collision(initial_state, k)
            initial_state = collision['final_state']
            self.collisions.append(collision)
        assert len(self.collisions) == self.max_k
        # 2 bytes is 1 block
        assert len(self.collisions[-1]['dummy_bytes']) == 2
        return self

    @staticmethod
    def second_preimage(hash_factory, msg):
        bs = 2
        msgblocks = len(msg) // bs
        k = int(math.floor(math.log(msgblocks, 2)))
        
        filename = 'em-%d.pickle' % k
        try:
            em = ExpandableMessage.deserialize(filename)
        except:
            em = ExpandableMessage(hash_factory, k).build()
            em.serialize(filename)

        final_state = em.collisions[-1]['final_state']
        
        h = hash_factory()
        for i in xrange(0, len(msg), bs):
            block = msg[i:i+bs]
            h.update(block)
            if final_state == h.digest():
                print 'Found bridge collision i=%d' % i
                break
        prefix_length = i + bs
        prefix = em.create_message(prefix_length)
        forgery = prefix + msg[i+bs:]
        return forgery

def test_prefix_creation():
    hash_factory = AESHash
    k = 3
    em = ExpandableMessage(hash_factory, k).build()
    
    all_zeros = em.create_message(3)
    print 'all_zeros', all_zeros.encode('hex')
    assert len(all_zeros) == 6
    assert all_zeros == ''.join([c['s1'] for c in em.collisions])

    all_ones = em.create_message(10)
    print 'all_ones', all_ones.encode('hex')
    assert all_ones == ''.join([c['dummy_bytes'] + c['s2'] for c in em.collisions])


if __name__ == '__main__':
    if len(argv) == 1:
        test_prefix_creation()

    hash_factory = AESHash
    with open(argv[1]) as msgfile:
        msg = msgfile.read()
        forgery = ExpandableMessage.second_preimage(hash_factory, msg)
        h1 = hash_factory().update(msg).digest()
        h2 = hash_factory().update(forgery).digest()
        assert h1 == h2
        print 'Successfully forged message!'
        forgery_file = argv[1] + 'second-preimage'
        with open(forgery_file, 'wb') as f:
            f.write(forgery)
        print 'Forgery saved to', forgery_file
