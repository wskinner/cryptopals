from rsa import *

# Why does the problem statement say the modulus is prime? The modulus n = pq
# is not prime, it is the product of two primes.
#
# In RSA, decryption raises the ciphertext to the d power mod N.
class ParityOracle(object):

    def __init__(self, rsa):
        self.rsa = rsa

    def check_parity(self, ciphertext):
        plaintext = self.rsa.decrypt(ciphertext)
        last_byte = plaintext[-1]
        return ord(last_byte) % 2 == 1

def crack_parity_oracle():
    rsa = RSA.new(1024)
    oracle = ParityOracle(rsa)

    secret = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='.decode('base64')

    ciphertext = rsa.encrypt(secret)
    e = rsa.e
    n = rsa.pubkey[1]

    rng = [0, n]
    i = 0
    # At each iteration i from 1, ciphertext is c * i * 2**e
    # 1: c * 2**e
    # 2: c**2 * 2**e * 2**e = c**2 * 4**e
    while rng[0] != rng[1]:
        ciphertext = (ciphertext * modexp(2, e, n)) % n
        bit = oracle.check_parity(ciphertext)

        if not bit:
            rng[1] = sum(rng) // 2
        else:
            rng[0] = sum(rng) // 2
        if rng[1] - rng[0] == 1:
            rng[0] += 1
        i += 1
        if i % 10 == 0:
            print rng[1] - rng[0]
    print 'Numeric plaintext:', rng[1]
    print 'Decrypted the message:', rsa.decode((rng[0]))

crack_parity_oracle()
