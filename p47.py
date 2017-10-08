from rsa import *
from util import keygen, modexp

# Implemented according to 
# http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html

def ceil(a, b):
    return -(-a // b)

def pkcs_pad(msg, bs):
    '''
    bs the block size in bytes
    '''
    padded_msg = '\x00\x02' + keygen(bs - 3 - len(msg)).replace('\x00', '\x01') + '\x00' + msg
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

def next_s(start):
    si = start
    while True:
        if pkcs1_oracle(rsa, (c0 * rsa._encrypt_num(si)) % n):
            print 'Found si', si
            return si
        si += 1

def step_2c(M, si_1):
    assert len(M) == 1
    a, b = next(iter(M))

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

def step3(M, si):
    B2, B3 = 2*B, 3*B
    Mi = set([])
    for a, b in M:
        rmin = ceil((a * si - 3 * B + 1), n)
        rmax = (b * si - 2 * B) // n + 1
        print '%s rmin %d\n%s rmax %d' % (type(rmin), rmin, type(rmax), rmax)
        assert rmin <= rmax
        print 'Considering %d r values' % (rmax - rmin)
        for r in range(rmin, rmax):
            aa = ceil(B2 + r * n, si)
            bb = (B3 - 1 + r * n) // si
            newa = max(a, aa)
            newb = min(b, bb)
            if newa <= newb:
                Mi |= set([(newa, newb)])
    return Mi

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
            interval = next(iter(M_i))
            if interval[1] - interval[0] == 1:
                break
        i += 1
    a, b = interval
    msga, msgb = pkcs_unpad(rsa.decode(a)), pkcs_unpad(rsa.decode(b))
    print msga, msgb
    assert msga == pt or msgb == pt
    print 'Cracked RSA'

if __name__ == '__main__':
    n_bits = 768
    n_bytes = n_bits / 8
    rsa = RSA.new(n_bits)

    pt = 'kick it, CC'
    msg = pkcs_pad(pt, n_bytes)
    print msg.encode('hex')
    ct = rsa.encrypt(msg)
    assert pkcs1_oracle(rsa, ct)

    n = rsa.pubkey[1]
    B = 2 ** (8 * (n_bytes - 2))

    i = 1
    M0 = set([(2 * B, 3 * B - 1)])

    s0 = 1
    c0 = (ct * rsa._encrypt_num(s0)) % n
    decrypt()
