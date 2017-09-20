from util import *
import random
import time

class MTStream:
    def __init__(self, seed):
        self.mt = MersenneTwister(seed)
        self.state = self.mt.randint()
        self.index = 0
        self.masks = (0xff, 0xff00, 0xff0000, 0xff000000)
    
    def next_byte(self):
        if self.index > 0 and self.index % 4 == 0:
            self.state = self.mt.randint()
        mask = self.masks[self.index % 4]
        b = self.srl((self.state & mask), (self.index % 4) * 8)
        self.index += 1
        return b

    def srl(self, x, bits): return x >> bits if x >= 0 else (x + 0x100000000) >> bits

    def encrypt(self, data):
        for c in data:
            yield chr(ord(c) ^ self.next_byte())

    def decrypt(self, data):
        return self.encrypt(data)

# Algorithm: brute force the 16 bit keyspace, each time creating a new MTS
# and drawing from it until we observe the known ciphertext sequence or reach
# a draw limit.
# ciphertext is plaintext, prefixed with some random bytes, encrypted with MTS
def find_key(ciphertext, plain):
    known = ciphertext[-len(plain):]
    print known.encode('hex'), len(known), 'bytes'
    for k in xrange(2**16):
        candidate = MTStream(k)
        enc_gen = candidate.encrypt('A' * len(ciphertext))
        candidate_ciphertext = stringify_stream(enc_gen)[-len(plain):]
        if k % 1000 == 0:
            print 'Tried', k, 'keys so far.', 'Candidate ciphertext is', candidate_ciphertext.encode('hex'), len(candidate_ciphertext), 'bytes'
        if candidate_ciphertext == known:
            print 'The guessed key is', k
            return k

def generate_token(nbytes, current_time_s):
    pad = 'A' * nbytes
    mt = MTStream(current_time_s)
    return stringify_stream(mt.encrypt(pad))

def check_token(token, current_time_s):
    pad = 'A' * len(token)
    mt = MTStream(current_time_s)
    return stringify_stream(mt.encrypt(pad)) == token

if __name__ == '__main__':
    mts = MTStream(0)
    for i in range(10):
        print mts.next_byte()

    mts = MTStream(0)
    enc = stringify_stream(mts.encrypt('hello world'))
    mts = MTStream(0)
    dec = stringify_stream(mts.decrypt(enc))
    assert dec == 'hello world'
    
    max_prefix_len = 1000
    prefix = keygen(random.randint(0, max_prefix_len))
    plain = 'A' * 14
    prefixed_plain = prefix + plain

    key = keygen(2)
    key_int = struct.unpack('<H', key)[0]
    print 'The actual key is', key_int
    mts = MTStream(key_int)
    ciphertext = stringify_stream(mts.encrypt(plain))
    if False: find_key(ciphertext, plaintext)
    
    t = int(time.time())
    token = generate_token(16, t)
    assert check_token(token, t)
