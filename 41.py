from util import *
from rsa import *
import random

# This works, because S**ed == S mod N. But why? Need to prove this with pen and
# paper. http://www.mathaware.org/mam/06/Kaliski.pdf

def test_modinv():
    x = 12
    a = 3
    n = 23
    
    assert modinv(x, a, n) == 6


class RSAOracle:
    def __init__(self, rsa):
        self._rsa = rsa
        self._seen = set()
        self.pubkey = rsa.pubkey

    def decrypt(self, c):
        if c in self._seen:
            return None
        self._seen.add(c)
        return self._rsa.decrypt(c)
    
def recover_unpadded(oracle, c):
    e, n = oracle.pubkey
    s = random.randint(2, n-1)
    cprime = (modexp(s, e, n) * c) % n 
    pprime = oracle.decrypt(cprime)
    # need to convert this back to numeric
    pprime = str_to_num(pprime)
    p = modinv(s, pprime, n)
    return num_to_str(p)

if __name__ == '__main__':
    test_modinv()
    
    rsa = RSA.new(1024)
    msg = 'Check out the hook while my DJ revolves it'
    c = rsa.encrypt(msg)
    oracle = RSAOracle(rsa)

    recovered = recover_unpadded(oracle, c)
    assert recovered == msg
    print 'Recovered the message', recovered
