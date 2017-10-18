
class Nostradamus(object):
    
    def __init__(self, hash_factory, k):
        self.hash_factory = hash_factory
        self.k = k
        assert k <= hash_factory().bs * 8
    
    def single_block_collision(self, initial_state1, initial_state2, bs):


    def build(self):
        
        return self
