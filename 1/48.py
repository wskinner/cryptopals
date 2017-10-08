from p47 import *

if __name__ == '__main__':
    n_bits = 768
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
