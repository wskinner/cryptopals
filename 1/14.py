from util import *
import random
import traceback

# For this one, we just need to figure out the length of the random string
# first. Then we can add enough bytes to fill out the first block, and 
# byte at a time decrypt string as before, ignoring the first block of 
# ciphertext. This generalizes to any number of random characters.
key = keygen()

secret = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'''
prefix_len = random.choice(range(16))
random_prefix = ''.join([chr(random.choice(range(256))) for i in range(prefix_len)])
# Given some bytes, oracle returns ecb(data || secret, key)
def encryption_oracle(data):
    payload = random_prefix + data + secret.decode('base64')
    return ecb_encrypt(payload, key)

# Return a dictionary mapping enc(input data || ch) to ch for 
# all ch in [0, 255]. Known should be of length bs - 1
def make_block_dict(known, bs=16, prefix=''):
    d = {}
    for i in range(0, 256):
        enc = encryption_oracle(prefix + known + chr(i))
        #print 'encrypting', known + chr(i)
        d[enc[16:32]] = chr(i)
    return d

# Given a known prefix of the secret string, decrypt the next 
# unknown character and return the character. If we know the first
# N characters of the secret, the next character to decrypt is N + 1
# If we know the first 0, pad to 15. If we know the first one, pad to 14.
# If we know the first two, pad to 13.
def decrypt_next(known, rpl):
    bs = 16
    # pad + known results in a string 1 character short of a whole number 
    # of blocks. 32 chars -> 15 pad, 31 chars -> 0 pad, 30 chars -> 1 pad etc.
    pad = (15 - (len(known) % bs)) * 'a'
    #print 'pad', pad
    payload = pad + known
    #print 'payload', payload
    assert bs - (len(payload) % bs) == 1
    prefix = (bs - rpl) * 'a'
    enc = encryption_oracle(prefix + pad)
    enc = enc[16:]
    #print 'enc', enc, len(enc)
    target_block_i = len(payload) / bs
    #print 'target_block_i', target_block_i
    target_block = payload[target_block_i * bs: target_block_i * bs + bs]
    #print 'target_block', target_block
    target_block_enc = enc[target_block_i * bs: target_block_i * bs + bs]
    #print 'target_block_enc', str_to_nums(target_block_enc)
    block_dict = make_block_dict(target_block, 16, prefix)
    ch = block_dict[target_block_enc]

    return ch


def get_random_prefix_len():
    pad = 'a' * 32
    prefix_len = 0
    while True:
        enc = encryption_oracle(pad)
        if len(enc) == 32: 
            break
        if enc[16:32] == enc[32:48]: 
            prefix_len = 16 - (len(pad) - 32)
            break
        pad += 'a'
    return prefix_len

if __name__ == '__main__':
    known = ''
    try:
        rpl = get_random_prefix_len()
        print 'rpl', rpl
        while True:
            next = decrypt_next(known, rpl)
            known += next
    except Exception, e:
        traceback.print_exc()
        print known
