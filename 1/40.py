from rsa import *
from util import *

# RSA Broadcast attack
# The Chinese Remainder Theorem says that if we have e.g. m1, m2, m3
# pairwise coprime, then the system of equations
#   x = a1 mod m1
#   x = a2 mod m2
#   x = a3 mod m3
# has a unique solution for x modulo M, where M = m1 * m2 * m3.
#
# In this excercise, we are given trying to solve for a1, a2, a3. 
#   a1 = m**3 mod n1
#   a2 = m**3 mod n2
#   a3 = m**3 mod n3
# Where the a's are the ciphertexts, computed by modular exponenetiation of the
# message modulo each public key (the n's). Since we know the n's and the a's,
# we can find x according to the CRT.
def test_cuberoot():
    print 'Testing cube root'
    x = 3
    cubed = 27
    assert cube_root(cubed) == x

    x = 12345678987654323456789098
    cubed = x**3
    assert cube_root(cubed) == x

def crack_rsa_broadcast(c0, c1, c2,
                        n0, n1, n2):

    assert n0 != n1
    assert n1 != n2
    M = n0 * n1 * n2
    ms0 = M // n0
    assert ms0 * n0 == M
    ms1 = M // n1
    assert ms1 * n1 == M
    ms2 = M // n2
    assert ms2 * n2 == M

    assert gcd(n0, n1) == 1
    assert gcd(n1, n2) == 1
    assert gcd(n2, n0) == 1

    sum1 = (c0 * ms0 * invmod(ms0, n0))
    sum2 = (c1 * ms1 * invmod(ms1, n1))
    sum3 = (c2 * ms2 * invmod(ms2, n2))
    result = sum1 + sum2 + sum3
    result = result % M

    rsa = RSA()
    return rsa.decode(cube_root(result))

def test_long():
    msg = 'Cooking MCs like a pound of bacon'

    key0 = RSA.new(1024)
    key1 = RSA.new(1024)
    key2 = RSA.new(1024)

    c0, c1, c2 = [k.encrypt(msg) for k in (key0, key1, key2)]
    n0, n1, n2 = [k.pubkey[1] for k in (key0, key1, key2)]

    assert key0.decrypt(c0) == msg
    assert key1.decrypt(c1) == msg
    assert key2.decrypt(c2) == msg

    print 'Cracking broadcast RSA'
    result = crack_rsa_broadcast(c0, c1, c2, n0, n1, n2)
    print 'The message is', result

def test_short():
    msg = 'A'

    key0 = RSA.new(p=23, q=29)
    key1 = RSA.new(p=47, q=41)
    key2 = RSA.new(p=53, q=59)

    c0, c1, c2 = [k.encrypt(msg) for k in (key0, key1, key2)]
    n0, n1, n2 = [k.pubkey[1] for k in (key0, key1, key2)]

    assert key0.decrypt(c0) == msg
    assert key1.decrypt(c1) == msg
    assert key2.decrypt(c2) == msg

    print 'Cracking broadcast RSA'
    result = crack_rsa_broadcast(c0, c1, c2, n0, n1, n2)
    print 'The message is', result

if __name__ == '__main__':
    test_cuberoot()
    test_short()
    test_long()
