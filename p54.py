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
        self.hash_factory = hash_factory
        self.k = k
        self.blocksize = blocksize

        self.layers = []
        self.entry_points = {}

    def add_layer(self):
        '''
        Adds a single layer to self.layers. Intended to be called repeatedly in
        order to generate the full collision pyramid. Each cell in each layer is
        a dictionary containing the final hash state of that cell, as well as the 
        inbound edges that produce the collision.
        The final result after calling the function k times is a list of lists of
        collisions, where the 0th list contains 2^k starting hash states, and the 
        k-1th list contains just one, the root of the collision tree.
        '''
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
                print 'Found collision', collision
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
        
        We can think of the collisions as a pyramid of k layers, with the bottom layer 
        having 2^(k-1) hash states, and the top layer having 1 hash state. It doesn't
        have to be a power of 2, but that simplifies the code.

        For each layer but the bottom one, each state in the layer has an inbound edge
        from two adjacent states in the layer below. Each edge corresponds to the 
        single block which causes the two lower states to collide into the upper one.
        '''
        suffix = ''
        prev_layer_index = entry_point_index
        for layer in self.layers[1:]:
            cur_layer_index = prev_layer_index // 2
            cell = layer[cur_layer_index]
            if prev_layer_index % 2 == 0:
                suffix += cell['s1']
            else:
                suffix += cell['s2']
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

        prehash = self.hash_factory().update(msg + glue_bytes)

        # At this point, we have blocksize bytes remaining to play with in order
        # force a collision into the collision pyramid.
        
        for st in generate_strings(self.blocksize):
            h1 = prehash.clone().update(st).digest()
            if h1 in self.entry_points:
                bridge_block = st
                entry_point_index = self.entry_points[h1]
                break
        if bridge_block is None:
            raise Exception('No bridge into the collision pyramid found')

        prefix = msg + glue_bytes + bridge_block
        suffix = self.build_collision_path(entry_point_index)

        assert self.hash_factory().update(prefix).digest() == self.layers[0][entry_point_index]['final_state']
        assert self.hash_factory(h=self.layers[0][entry_point_index]['final_state']).update(suffix).digest() == self.layers[-1][0]['final_state']

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

    k = 6
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
