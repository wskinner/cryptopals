from dsa import *
from util import *
from hashlib import sha1
from itertools import combinations

y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

def parse_messages(filename):
    packed = []
    with open(filename) as f:
        msg = None
        s = None
        r = None
        m = None
        for i, line in enumerate(f):
            content = line.split(': ')[1]
            if i % 4 == 0:
                msg = content[:-1]
            if i % 4 == 1:
                s = int(content)
            if i % 4 == 2:
                r = int(content)
            if i % 4 == 3:
                m = int(content.replace(' ', ''), 16)
                packed.append((r, s, msg, m))

        return packed

def extract_k(z1, z2, s1, s2, q):
    return ((z1 - z2) * invmod(s1 - s2, q)) % q

def check(msg1, msg2, q, fingerprint):
    z1, z2 = msg1[3], msg2[3]
    s1, s2 = msg1[1], msg2[1]
    k = extract_k(z1, z2, s1, s2, q)
    x = CrackDSA.solve_x(s1, k, z1, msg1[0], q)

    digest = sha1()
    digest.update(hex(x)[2:-1])
    if digest.hexdigest() == fingerprint:
        return x
    return None

def test_repeated_nonce():
    print 'Testing repeated nonce math'
    dsa = DSA.new()
    msg1 = 'Cooking MCs like a pound of bacon'
    msg2 = 'I go crazy when I hear a cymbal'

    k = 9001
    k_inv = invmod(k, dsa.params.q)

    r1, s1 = dsa.sign(msg1, k, k_inv)
    r2, s2 = dsa.sign(msg2, k, k_inv)

    digest = dsa.digest()
    digest.update(msg1)
    hsh1 = digest.digest()
    z1 = dsa.leftmost(hsh1)
    digest = dsa.digest()
    digest.update(msg2)
    hsh2 = digest.digest()
    z2 = dsa.leftmost(hsh2)
    
    assert  extract_k(z1, z2, s1, s2, dsa.params.q) == k
    print 'Done testing repeated nonce math'

def break_repeated_nonce():
    filename = '44.txt'
    fingerprint = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    data = parse_messages(filename)
    for d in data:
        digest = sha1()
        digest.update(d[2])
        hexdigest = int(digest.hexdigest(), 16)
        assert hexdigest == d[3]

    for pair in combinations(data, 2):
        key_or_none = check(pair[0], pair[1], Q, fingerprint)
        if key_or_none is not None:
            print 'Cracked private key', key_or_none
            break

test_repeated_nonce()
break_repeated_nonce()
