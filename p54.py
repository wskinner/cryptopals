from itertools import islice
import math

from util import *
from p52 import AESHash

class Nostradamus(Serializable):
    '''
    The structure of a prediction is 
    Prediction Text | glue | suffix
    where Prediction Text is the actual prediction being made, glue is some
    random bytes which can be varied to make sure that hash(Prediction Text | glue)
    collides with one of the initial state leaves at the bottom of the collision pyramid,
    and suffix is the path from that leaf to the root, guaranteeing that the whole
    package hashes to the root value of the pyramid.

    We will have k + 1 layers, with the bottom layer having 2^k entry points into the pyramid.
    '''
    
    def __init__(self, hash_factory, k, blocksize):
        # This is not strictly necessary, I'm just being lazy
        if math.log(pow(2, k), 2) != k:
            raise Exception('k must be a power of 2')

        self.hash_factory = hash_factory
        self.k = k
        self.blocksize = blocksize
        assert k <= hash_factory().bs * 8
        self.layers = []
        self.entry_points = {}

    def add_layer(self):
        if len(self.layers) == 0:
            self.layers = [[{'final_state': st} for st in islice(generate_strings(self.blocksize), int(2**self.k))]]
        else:
            newlayer = []
            current_layer = self.layers[-1]
            print 'Previous layer has %d items' % len(self.layers[-1])
            for i in xrange(0, len(self.layers[-1]), 2):
                h1 = current_layer[i]['final_state']
                h2 = current_layer[i+1]['final_state']
                collision = single_block_collision(self.hash_factory, h1, h2, self.blocksize)
                #print 'Found collision', collision
                newlayer.append(collision)
            self.layers.append(newlayer)

    def build(self):
        for i in xrange(self.k, -1, -1):
            print 'Adding layer %d' % i
            self.add_layer()
    
        for i, h in enumerate(self.layers[0]):
            self.entry_points[h['final_state']] = i

        return self
    
    def build_collision_path(self, entry_point_index):
        '''
        Returns a string that hashes to the root of the collision pyramid, starting
        from the hash state at self.layers[entry_point_index]

        Invariant:
        Where level 0 is the top of the pyramid, and level k-1 the bottom, and
        level k-1 has a length that is a power of 2:
        At level l > k-1, each index i has an edge to the collision at index 
        i // 2 in level l-1.
        '''
        print 'build_collision_path, entry_point_index=%d, bottom layer length=%d' % (entry_point_index, len(self.layers[0]))
        suffix = ''
        prev_layer_index = entry_point_index
        print len(self.layers)
        for layer in self.layers[1:]:
            cur_layer_index = prev_layer_index // 2
            if prev_layer_index % 2 == 0:
                suffix += layer[cur_layer_index]['s1']
            else:
                suffix += layer[cur_layer_index]['s2']
            prev_layer_index = cur_layer_index
            
        digest = self.hash_factory()
        digest.h = self.layers[0][entry_point_index]['final_state']
        
        assert digest.update(suffix).digest() == self.layers[-1][0]['final_state']
        return suffix

    def predict(self, msg_template, glue_bytes=256):
        '''
        In a real implementation of this attack, the glue bytes would go somewhere
        else, like in a hidden image in a PDF.

        The buffer bytes let us account for message length variability. Not all
        the possible outcomes we are predicting will have the same length, and
        the buffer bytes allow us to have a consistent final document length. The
        message template gives us a rough length estimate to expect for the final
        message.
        '''
        padlen = len(msg_template) + glue_bytes
        assert len(self.layers[-1]) == 1
        return padlen, self.layers[-1][0]['final_state']

    def forge(self, msg, target_length_bytes):
        '''
        Create a full message payload that hashes to the root of the collision tree.
        '''
        msg_bytes = len(msg)
        suffix_bytes = self.blocksize * self.k
        bridge_bytes = self.blocksize
        glue_needed = target_length_bytes - msg_bytes - suffix_bytes - bridge_bytes
        
        glue_bytes = glue_needed * '\x00'
        while (len(msg) + len(glue_bytes)) % self.blocksize != 0:
            glue_bytes += '\x00'

        print '! msgglue length', len(msg) + len(glue_bytes)
        prehash = self.hash_factory().update(msg + glue_bytes)

        # At this point, we have blocksize bytes remaining to play with in order
        # force a collision into the collision pyramid.
        
        for st in generate_strings(self.blocksize):
            h1 = prehash.clone().update(st).digest()
            if h1 in self.entry_points:
                entry_point_block = st
                entry_point_index = self.entry_points[h1]
                break
        if entry_point_block is None:
            raise Exception('No bridge into the collision pyramid found')

        print '?', len(msg) + len(glue_bytes) + len(entry_point_block)

        print '!', len(glue_bytes)
        prefix = msg + glue_bytes + entry_point_block

        suffix = self.build_collision_path(entry_point_index)
        assert self.hash_factory().update(prefix).digest() == self.layers[0][entry_point_index]['final_state']
        assert self.hash_factory(h=self.layers[0][entry_point_index]['final_state']).update(suffix).digest() == self.layers[-1][0]['final_state']
        print 'prefixlen', len(prefix)
        print 'suffixlen', len(suffix)
        payload = prefix + suffix
        
        return payload

    def print_layers(self):
        for l in reversed(self.layers):
            hexlayer = []
            for c in l:
                hexlayer.append({k: v.encode('hex') for k, v in c.iteritems()})
            print hexlayer

if __name__ == '__main__':
    msg_template = '''
    Giants %d, Dodgers %d
    A's %d, Angels %d
    '''

    k = 3
    bs = 2
    hash_factory = AESHash
    filename = 'nostradamus-%d-%d.pickle' % (k, bs)
    try:
        nostradamus = Nostradamus.deserialize(filename)
    except:
        nostradamus = Nostradamus(hash_factory, k, bs).build()
        nostradamus.serialize(filename)
    
    target_length, fingerprint = nostradamus.predict(msg_template)
    actual_scores = [
            (10, 5, 5, 3),
            (7, 6, 2, 9)
            ]

    for scoreset in actual_scores:
        msg = msg_template % scoreset
        payload = nostradamus.forge(msg, target_length)
        assert hash_factory().update(payload).digest() == fingerprint

    print 'Successfully forged %d outcomes' % len(actual_scores)
