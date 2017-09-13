from util import *
import random
import sys

data = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]
key = keygen()
#st = random.choice(data).decode('base64')

def choose_and_encrypt(st):
    st = st.decode('base64')
    iv = keygen()
    return cbc_encrypt(st, key, iv), iv

def check(ciphertext, iv):
    plaintext = cbc_decrypt(ciphertext, key, iv)
    return padding_valid(plaintext)

# The last block will have between 1 and blocksize (inclusive) padding bytes.
def count_padding_bytes(c1, c2):
    # last byte means we need to see how many padding bytes the 
    # plaintext has. If we accidentally picked 
    padding_bytes = 1
    for b in range(15):
        p = keygen(b+1) + c1[b+1:]
        if not check(c2, p):
            # plaintext has 16 - b bytes of padding
            return 16 - b
    return padding_bytes

# b-1 xor d-1 == p-1, so b-1 xor d-1 xor p-1 == 0x00.
# Therefore b-1 xor d-1 xor p-1 xor X == X.
def decrypt_block(c1, c2, padding_bytes=0):
    c1_mod = c1
    
    plain = ''.join([chr(padding_bytes) for i in range(padding_bytes)])
    for i in range(padding_bytes, 16):
        # index of the character we are currently decrypting
        index = 15 - i
        pad = ''.join([chr(i+1) for j in range(i+1)])
        for z in range(256):
            payload = chr(z) + plain
            payload = xor_byte_strings(payload, pad)
            cn1 = c1[index:]
            payload = xor_byte_strings(payload, cn1)
            full_payload = keygen(16 - len(payload)) + payload
            if check(c2, full_payload):
                                
                plain = chr(z) + plain
                break
    return plain
        
# Method:
# Let Db be the output of the block cipher for byte b
# Let Cn be the nth byte of a ciphertext block
# 
# We will decrypt the last byte first, then the second to last, 
# and so on.
# Mutate the last byte of Cn-1 to be 0x01 xor g-1, where g-1 is a guess for
# the last byte of Pn. We need to try at most 255 values of g-1. If the padding is
# valid, that means we guessed the right byte, because 0x01 xor g-1 xor Dn-1 ==
# 0x01 xor 0x00 == 0x01, which is valid padding for the last byte. Now that we know
# the last byte g-1, we mutate Cn-1 to contain 0x02 xor g-1 as its last byte, and 
# perform the same routine to guess the second to last byte, guessing Cn-2 as
# 0x02 xor g-2 and so on.
def decrypt():
    lines = []
    for st in data:
        c, iv = choose_and_encrypt(st)
        check(c, iv)
        msg = ''
        blocks = [iv] + [c[i:i+16] for i in range(0, len(c), 16)]
        padding_bytes = count_padding_bytes(blocks[-2], blocks[-1])
        while len(blocks) > 1:
            msg = decrypt_block(blocks[-2], blocks[-1], padding_bytes) + msg
            padding_bytes = 0
            blocks = blocks[:-1]
        lines.append(msg)
    return '\n'.join(lines)

if __name__ == '__main__':
    assert padding_valid('foo' + chr(13) * 13)
    assert padding_valid('h' * 16 + chr(16) * 16)
    assert not padding_valid('foobar')
    assert not padding_valid('696e670d0d0d0d0d0d0d0d0d0d0d0d00'.decode('hex'))
    iv = keygen()
    assert len(cbc_encrypt('h' * 16, key, iv)) == 32
    assert len(cbc_encrypt('h' * 15, key, iv)) == 16
    print decrypt()
