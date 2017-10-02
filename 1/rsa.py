import subprocess
from util import modexp, num_to_str, str_to_num

def generate_prime(min_bits=4096):
    bits = str(int(min_bits))
    return int(subprocess.check_output(['/usr/local/opt/openssl@1.0/bin/openssl', 'prime', '-generate', '-bits', bits, '-hex']).strip(), 16)

# If a has a multiplicative inverse mod m, gcd(a, m) == 1
def egcd(a, m):
    s, old_s = (0, 1)
    t, old_t = (1, 0)
    r, old_r = (m, a)

    while r != 0:
        # is the integer division of old_r and r
        quotient = old_r / r

        # r is the integer remainder of old_r / r
        old_r, r = (r, old_r - quotient * r)

        # s is the integer remainder of old_s / s
        old_s, s = (s, old_s - quotient * s)

        # t is the integer remainder of old_t / t
        old_t, t = (t, old_t - quotient * t)

    coefficients = (old_s, old_t)
    gcd = old_r
    return gcd, coefficients

def gcd(a, m):
    return egcd(a, m)[0]

def invmod(a, m):
    gcd, coefficients = egcd(a, m)
    result =coefficients[0] % m
    print 'invmod', a, m, result
    return result

def test_egcd():
    print 'Testing egcd'
    print 'Computing egcd(240, 46)'
    gcd, coefficients = egcd(240, 46)

    assert gcd == 2

    print 'Computing egcd(17, 3120)'
    gcd, coefficients = egcd(17, 3120)
    assert gcd == 1

def test_invmod():
    print 'Testing invmod'
    print 'Computing invmod(17, 3120)'
    assert invmod(17, 3120) == 2753

def test_encrypt_decrypt():
    print 'Testing encryption'
    msg = 'Cooking MCs like a pound of bacon'
    
    rsa = RSA.new()
    print 'Encrypting message:', msg
    ciphertext = rsa.encrypt(msg)
    print 'Ciphertext', ciphertext
    
    plain = rsa.decrypt(ciphertext)
    print 'Decrypted message:', plain
    assert plain == msg


class RSA:
    def __init__(self, e=None, n=None, d=None):
        self.pubkey = (e, n)
        self.privkey = (d, n)

    # Generate a new RSA keypair
    @staticmethod
    def new(n_bits=2048, p=None, q=None):
        if p is None and q is None:
            p = generate_prime(n_bits)
            q = generate_prime(n_bits)
            
        n = p * q
        et = (p - 1) * (q - 1)

        e = 3
        
        d = invmod(e, et)
        r = RSA(e, n, d)
        r.p = p
        r.q = q
        r.e = e
        r.d = d
        return r

    def _encrypt_num(self, num):
        c = modexp(num, self.pubkey[0], self.pubkey[1])
        return c

    # Encrypt for this keypair
    def encrypt(self, msg):
        return self._encrypt_num(self.encode(msg))

    def _decrypt_num(self, num):
        return modexp(num, self.privkey[0], self.privkey[1])

    # Ciphertext is a string (e.g. ascii armored)
    def decrypt(self, ciphertext_num):
        return self.decode(self._decrypt_num(ciphertext_num))

    def encode(self, st):
        return str_to_num(st)
        
    def decode(self, num):
        return num_to_str(num)

    def __str__(self):
        return 'RSA Keypair: p=%d, q=%d, e=%d, d=%d' % (self.p, self.q, self.e, self.d)

if __name__ == '__main__':
    test_egcd()
    test_invmod()
    test_encrypt_decrypt()
