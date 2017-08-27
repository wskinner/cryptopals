from util import keygen, cbc_encrypt, ecb_encrypt, pkcs7_pad
from Crypto.Random import random
from Crypto import Random
from collections import Counter

secret = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'''
key = keygen()
def encryption_oracle(data):
    padded = pkcs7_pad(data + secret.decode('base64'))
    return ecb_encrypt(data, key)


