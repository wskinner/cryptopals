from util import *

class API:

    def __init__(self):
        self.key = keygen()
        self.nonce = 0

    def encrypt(self, plain):
        return stringify_stream(ctr_encrypt(plain, self.key, self.nonce))

    def edit(self, ciphertext, offset, newtext):
        plain_pre = stringify_stream(ctr_decrypt(ciphertext[:offset], self.key, self.nonce))
        plain = plain_pre + newtext
        cipher_post = ciphertext[len(plain):]
        return stringify_stream(ctr_encrypt(plain, self.key, self.nonce)) + cipher_post

f = open('25.txt')
ciphertext = f.read().decode('base64')
f.close()
plaintext = ecb_decrypt(ciphertext, 'YELLOW SUBMARINE')

# Method: for each block of ciphertext c1, we can edit that block to a different block
# c2. Then we have 
# c1 = p xor key
# c2 = known xor key.
# key = c2 xor known
# p = c1 xor key

api = API()
ctr_ct = api.encrypt(plaintext)

plain = []
for i in xrange(0, len(ctr_ct), 16):
    pad = 'A' * 16
    c1 = ctr_ct[i: i + 16]
    c2 = api.edit(ctr_ct, i, pad)[i:]
    key = xor_byte_strings(c2, pad)
    p = xor_byte_strings(c1, key)
    plain.append(p)

print ''.join(plain)
