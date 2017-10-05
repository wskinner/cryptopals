from dsa import *
from hashlib import sha1

def solve_x(s=None, k=None, z=None, r=None, q=None):
    return ((s * k - z) * invmod(r, q)) % q

class CrackDSA(DSA):
    def __init__(self, y, z, q):
        params = DSAParams.new()
        params.y = y
        super(CrackDSA, self).__init__(params, sha1)

        self.z = z
        self.q = q

    def leftmost(self, msg):
        return self.z

    def sign(self, msg, k, k_inv, x):
        self.params.x = x
        return super(CrackDSA, self).sign(msg, k, k_inv)

    def recover_key_from_nonce(self, msg, k, sig):
        candidate = solve_x(s=sig[1], k=k, z=self.z, r=sig[0], q=self.q)
        return candidate

def test_recover_key():
    print 'Testing key recovery'
    dsa = DSA(digest=sha1)
    k, k_inv = dsa.gen_k()
    msg = 'Cooking MCs like a pound of bacon'
    sig = dsa.sign(msg, k, k_inv)
    
    digest = sha1()
    digest.update(msg)

    crack = CrackDSA(dsa.params.y, dsa.leftmost(digest.digest()), dsa.params.q)
    x = crack.recover_key_from_nonce(msg, k, sig)
    assert x == dsa.params.x

    print 'Done testing key recovery'

def recover_key():
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    msg = '''For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
'''
    digest = sha1()
    digest.update(msg)
    assert digest.hexdigest() == 'd2d0714f014a9784047eaeccf956520045c45265'

    z = 0xd2d0714f014a9784047eaeccf956520045c45265
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    sig = (r, s)
    q = Q
    
    dsa = CrackDSA(y, z, q)
    assert dsa.validate(sig, msg)

    key_fingerprint = '0954edd5e0afe5542a4adf012611a91912a3ec16'
    for k in xrange(2**16):
        try:
            x = dsa.recover_key_from_nonce(msg, k, sig)
            candidate_sig = dsa.sign(msg, k, invmod(k, q), x)
            if candidate_sig == sig:
                print 'Cracked x', x
                break
        except:
            continue

if __name__ == '__main__':
    test_recover_key()
    recover_key()
