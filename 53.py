from util import *
from p52 import AESHash
import math
import pickle

class ExpandableMessage(object):
    
    def __init__(self, hash_factory, blocksize):
        '''
        blocksize in bytes
        '''
        self.hash_factory = hash_factory
        self.blocksize = blocksize
        self.collisions = []

    def find_collision(self, h, k):
        '''
        Find a collision between a single block message and a message of 2^(k-1) blocks
        '''
        blocksize = self.blocksize
        print 'find_collision(k, %d)' % (k)
        start = 2**((blocksize - 1) * 8)
        end = 2**(blocksize * 8)
        dummy_blocks = (self.blocksize * 2**(k-1)) * '\x00'
        dummy_hash = h()
        initial_state = dummy_hash.state()
        dummy_hash.update(dummy_blocks)

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
                    # At this point, we have:
                    # s1, a single block
                    # s2, a single block
                    # initial_state, a single block
                    #
                    # Starting from iniitial_state, hash(dummy_blocks | s2) == hash(s1).
                    # At the beginning, we generated a collision between a single 
                    # block and a block of length 2^(k-1) + 1 blocks, starting from the 
                    # default initial state. 
                    print 'Found collision from initial state = "%s"' % initial_state.encode('hex'), s1.encode('hex'), s2.encode('hex'), '->', h1.encode('hex')
                    self.collisions.append({
                        'initial_state': initial_state,
                        's1': s1,
                        's2': s2,
                        'dummy_blocks': dummy_blocks,
                        'final_state': h1
                        })
                    return h1
        print 'Failed to find a collision'

    @staticmethod
    def new(k, hash_factory=AESHash, blocksize=2):
        em = ExpandableMessage(hash_factory, blocksize)
        em.k = k

        em.prefix_lookups = [set() for i in range(k)]
        em.build_prefixes(k)

        initial_state = '\xff\xff'
        for i in range(k, 0, -1):
            intermediate_factory = lambda : hash_factory(h=initial_state)
            final_state = em.find_collision(intermediate_factory, i)
            initial_state = final_state

        return em

    def build_prefixes(self, k):
        if k == 1:
            result = set([1])
        else:
            result = set()
            for x in self.build_prefixes(k-1):
                result.add(x + 1)

                exp = 2**(k-1) + 1
                result.add(x + exp)
        self.prefix_lookups[k - 1] = result
        return result

    def test_prefix(self):
        pass

    def build_prefix(self, length):
        '''
        The expandable message is a k-bit string. The shortest prefix is k, 
        where we use the single block collision from each step. The longest is
        2^(k-1) + 2^(k-2) + 1 ... + 2 = k + 2^(k-1).
        If 0 denotes choosing the single block collision and 1, choosing the dummy
        padded collision, then a path through the message is just the binary 
        representation of the length minus k
        '''
        bits = length - self.k
        print 'Building prefix of length=%d (%d)' % (length, bits)
        prefix_builder = []
        num = bin(bits)[2:]
        print num
        while len(num) < self.k:
            num = '0' + num
        for i, bit in enumerate(num):
            print i, bit
            if bit == '0':
                prefix_builder.append(self.collisions[i]['s1'])
            else:
                prefix_builder.append(self.collisions[i]['dummy_blocks']) 
                prefix_builder.append(self.collisions[i]['s2'])
            sofar = ''.join(prefix_builder)
            print 'hashing intermediate prefix value of length', len(sofar)
            assert self.hash_factory().update(sofar).digest() == self.collisions[i]['final_state']
        return ''.join(prefix_builder)
    
    def crack(self, msg):
        h = self.hash_factory()
        # Maps intermediate states of the hash to the index of the msg such that
        # hashing msg[:index + 1] produces that hash state.
        final_state = self.collisions[-1]
        print final_state
        intermediate_states = {}
        for i, b in enumerate(msg):
            h.update(b)
            intermediate_states[h.state()] = i
            if h.state() == final_state['final_state']:
                # now we have b such that b == hash(msg[:msg_index+1])
                bridge = h.state()
                bridge_index = i
                break
        print len(intermediate_states), 'intermediate hash states'
        
        prefix = self.build_prefix(bridge_index + 1)
        print 'done building prefix'

        payload = prefix + msg[bridge_index+1:]
        print 'done building payload'
        
        assert self.hash_factory().update(prefix).digest() == bridge
        print 'prefix is correct'
        assert self.hash_factory().update(payload).digest() == \
                self.hash_factory().update(msg).digest()
    
    def serialize(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self, f)
    
    @staticmethod
    def deserialize(filename):
        with open(filename, 'rb') as f:
            return pickle.load(f)


if __name__ == '__main__':
    with open('pg98-images.mobi') as f:
        msg = f.read().strip()

    em_length = int(math.floor(math.log(len(msg), 2)))
    try:
        em = ExpandableMessage.deserialize('em.pickle')
    except:
        em = ExpandableMessage.new(em_length)
        em.serialize('em.pickle')
    em.crack(msg)
