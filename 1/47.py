from rsa import *
from util import keygen, modexp
import math

# I had a lot of trouble with this problem, and based my solution on 
# https://github.com/ctz/cryptopals/blob/master/mcp47.py

def ceil(a, b):
    return -(-a // b)

def pkcs_pad(msg, bs):
    '''
    bs the block size in bytes
    '''
    # For some reason the algorithm is not very reliable. It doesn't work with all 
    # paddings.
    #padded_msg = '\x00\x02' + keygen(bs - 3 - len(msg)).replace('\x00', '\x01') + '\x00' + msg
    padded_msg = '\x00\x02' + '40e5d4b5cf48daf14c51b422c86345ec1ccd'.decode('hex') + '\x00' + msg
    assert len(padded_msg) == bs
    return padded_msg

def pkcs_unpad(msg):
    print 'Unpadding msg', msg.encode('hex')
    i = 2
    assert msg[:2] == '\x00\x02'
    while msg[i] != '\x00':
        i += 1
    return msg[i+1:]

def pkcs1_oracle(rsa, cipher):
    plain = rsa.decrypt(cipher)
    return plain[:2] == '\x00\x02'

# This function does three things: it merges overlapping intervals, ignores disjoint
# intervals, and when an interval is contained inside another, saves the smaller one.
def merge(A, B):
    print 'A, B', A, B
    Ai = 0
    Bi = 0
    out = []
    while Ai < len(A) and Bi < len(B):
        # u, v is the current interval in A
        u, v = A[Ai]
        # x, y is the current interval in B
        x, y = B[Bi]

        # Convention is that we are
        # Keeping the interval with the lower start in A.
        if x < u:
            print 'Swapping'
            A, B = B, A
            Ai, Bi = Bi, Ai
            u, v, x, y = x, y, u, v

        # B entirely contained within A
        if u <= x <= y <= v:
            out.append((x, y))
            Bi += 1
            continue

        # disjoint
        if v <= x:
            Ai += 1
            continue

        out.append((x, v))
        Ai += 1

    print 'merge', out
    return out

def next_s(start):
    si = start
    while True:
        if pkcs1_oracle(rsa, (c0 * rsa._encrypt_num(si)) % n):
            print 'Found si', si
            return si
        si += 1

def step_2c(M, si_1):
    assert len(M) == 1
    a, b = M[0]

    ri = ceil(2 * (b * si_1 - 2 * B), n)
    while True:
        si = (2 * B + ri * n) // b
        
        while si <= (3 * B + ri * n) // a:
            if pkcs1_oracle(rsa, (c0 * rsa._encrypt_num(si)) % n):
                return si
            si += 1
        ri += 1

def step2(i, M, si_1):
    if i == 1:
        # step 2a
        return next_s(ceil(n, 3 * B))
    elif len(M) > 1:
        # step 2b
        return next_s(si_1 + 1)
    else:
        # step 2c
        return step_2c(M, si_1)
    
def decrypt():
    s_i = s0
    M_i = M0
    i = 1

    while True:
        # step 2
        s_i = step2(i, M_i, s_i)

        # step 3
        M_i = step3(M_i, s_i)
        if len(M_i) == 1:
            if M_i[0][1] - M_i[0][0] == 1:
                break
        i += 1
    a, b = M_i[0]
    msga, msgb = pkcs_unpad(rsa.decode(a)), pkcs_unpad(rsa.decode(b))
    print msga, msgb
    assert msga == pt or msgb == pt
    print 'Cracked RSA'

def step3(M, si):
    Mi = []
    for a, b in M:
        rmin = (a * si - 3 * B + 1) / n
        rmax = (b * si - 2 * B) / n
        assert rmin <= rmax
        
        r = rmin
        while r <= rmax:
            lower = ceil(2 * B + r * n, si)
            upper = (3 * B - 1 + r * n) // si
            assert lower <= upper
            Mi.append((lower, upper))
                
            r += 1
            
    return merge(Mi, M)

if __name__ == '__main__':
    pub = (3, 74947272414376228856426297251880048245578115594530376819126732128797690068357L)
    priv = (49964848276250819237617531501253365496682993187482651792498877021334135052147L, 74947272414376228856426297251880048245578115594530376819126732128797690068357L)
    n_bits = 256
    n_bytes = n_bits / 8
    rsa = RSA(e=pub[0], n=pub[1], d=priv[0], n_bits=n_bits)

    pt = 'kick it, CC'
    msg = pkcs_pad(pt, n_bytes)
    print msg.encode('hex')
    ct = rsa.encrypt(msg)
    assert pkcs1_oracle(rsa, ct)
    n = rsa.pubkey[1]
    B = 2 ** (8 * (n_bytes - 2))

    # don't need to do blinding here
    i = 1
    M0 = [(2 * B, 3 * B - 1)]

    s0 = 1
    c0 = (ct * rsa._encrypt_num(s0)) % n
    decrypt()
