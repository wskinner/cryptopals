from dsa import *
from hashlib import sha256

# This attack works because setting G to 1 mod p means that y will always be y,
# since y is calculated as modexp(g, x, p), i.e. y == g == 1 mod p.
# During signature verification, the verifier calculates ((v1 * v2) mod p) mod q,
# where v1 is modexp(g, k1, p) and v2 is modexp(y, k2, p). It doesn't matter 
# what the constant values are, as the base is 1. Therefore, the verifier simply
# checks 1 == r, and we can forge a signature by setting r = 1.

# Using 0 or P for G doesn't work because those numbers have no inverse mod Q
def test_parameters():
    print 'Testing various g parameters'
    print 'Trying g=0'
    try:
        g = 0
        params = DSAParams.new(g)
        dsa = DSA(params)

        msg = 'Cooking MCs like a pound of bacon'
        sig = dsa.sign(msg)
    except Exception as e:
        print e
    
    print 'Trying g=1'
    try:
        g = 1
        params = DSAParams.new(g)
        dsa = DSA(params)

        msg = 'Cooking MCs like a pound of bacon'
        sig = dsa.sign(msg)
        print 'Signed msg "%s". Signature = %s' % (msg, sig)
    except Exception as e:
        print e

    try:
        print 'Trying g=p+1'
        g = P + 1
        params = DSAParams.new(g)
        dsa = DSA(params)

        msg = 'Cooking MCs like a pound of bacon'
        sig = dsa.sign(msg)
        print 'Signed msg "%s". Signature = %s' % (msg, sig)
    except Exception as e:
        print e
    print 'Done testing various g parameters'

# Given a public key and the digest algorithm used by the signer, forge a signature
# for any message (assuming the signer was induced to use the parameter g = p + 1.
def forge_signature(msg, digest, y, p=P, q=Q):
    hasher = digest()
    hasher.update(msg)
    z = DSA.new().leftmost(hasher.digest())
    r = modexp(y, z, p) % q
    s = (r * invmod(z, q)) % q
    return r, s

def test_forge_signature():
    print 'Forging signatures'
    dsa = DSA(DSAParams.new(P + 1), digest=sha256)
    print 'Params', dsa.params
    
    msg1 = 'With a mind to rhyme and two hyped feet'
    sig1 = dsa.sign(msg1)
    print 'Valid signature', sig1
    assert dsa.validate(sig1, msg1)

    msg2 = 'Hello, World'
    sig2 = forge_signature(msg2, sha256, dsa.params.y)
    print 'Forged signature', sig2
    assert dsa.validate(sig2, msg2)

    msg3 = 'Goodbye, World'
    sig3 = forge_signature(msg3, sha256, dsa.params.y)
    print 'Forged signature', sig3
    assert dsa.validate(sig3, msg3)
    print 'Done forging signatures'

test_parameters()
test_forge_signature()
