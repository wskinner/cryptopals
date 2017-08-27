from util import keygen, cbc_encrypt, ecb_encrypt, pkcs7_pad, is_ecb
from Crypto.Random import random
from Crypto import Random
from collections import Counter

def encryption_oracle(data):
    prepad = Random.get_random_bytes(random.choice(range(5, 11)))
    postpad = Random.get_random_bytes(random.choice(range(5, 11)))
    padded = pkcs7_pad(prepad + data + postpad)
    key = keygen()
    if random.choice(range(2)) == 0:
        iv = keygen()
        return cbc_encrypt(data, key, iv)
    else:
        return ecb_encrypt(data, key)

if __name__ == '__main__':
    for i in range(10):
        print is_ecb(encryption_oracle)
