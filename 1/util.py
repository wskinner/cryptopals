from Crypto.Cipher import AES
from Crypto import Random

def xor_strings(a, b):
    if len(a) != len(b):
        raise Exception('strings must be the same length')
    return xor_byte_strings(a.decode('hex'), b.decode('hex')).encode('hex')

def xor_byte_strings(a, b):
    a_numeric = map(ord, a)
    b_numeric = map(ord, b)
    xored = ''.join([chr(x^y) for (x, y) in zip(a_numeric, b_numeric)])
    return xored

# XOR a byte string against a single character
def single_xor(string, char):
    pad = char * len(string)
    return xor_byte_strings(pad, string)

def encrypt_repeating_key_xor(data, key):
    key_expanded = [key[i % len(key)] for i in range(len(data))]
    return xor_byte_strings(data, key_expanded)

# left pads a string of ones and zeroes to 8 characters
def pad_to_8(x):
    bits_to_add = 8 - len(x)
    return '0' * bits_to_add + x

def hamming(a, b):
    a_bin = ''.join([pad_to_8(format(ord(x), 'b')) for x in a])
    b_bin = ''.join([pad_to_8(format(ord(x), 'b')) for x in b])
    count = 0
    for i in range(len(a_bin)):
        if a_bin[i] != b_bin[i]: count += 1
    return count

def guess_single_xor_key(data):
    letters = set(range(97, 123)) # lowercase more likely
    attempts = []
    for i in range(256):
        xored = single_xor(data, chr(i))
        count = len([a for a in xored if a in letters]) / float(len(xored))
        attempts.append((count, i))
    attempts = list(reversed(sorted(attempts)))
    print attempts[:3]
    return attempts[0][1]

def pkcs7_pad(data, bs=16):
    padding_needed = bs - len(data) % bs
    return data + chr(padding_needed) * padding_needed

# AES-128 encrypt with cbc mode 
# Ci = AES(Pi xor Ci-1)
def cbc_decrypt(data, key, iv, bs=16):
    aes = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(data)
    plain_blocks = []
    prev_cipher_block = iv
    for i in range(0, len(data) - bs, bs):
        block = data[i:i+bs]
        plain = xor_byte_strings(aes.decrypt(block), prev_cipher_block)
        prev_cipher_block = block
        plain_blocks.append(plain)

    return ''.join(plain_blocks)

def ecb_encrypt(data, key, bs=16):
    aes = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(data)
    return aes.encrypt(padded)

def cbc_encrypt(data, key, iv, bs=16):
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(data)
    return aes.encrypt(padded)

def keygen(bs=16):
    return Random.get_random_bytes(bs)

def is_ecb(f):
    # except for the first and last cypher block, all will be the same
    plain = 'a' * 16 * 4
    cypher = f(plain)
    b2 = cypher[16:32]
    b3 = cypher[32:48]
    return b2 == b3

def ecb_blocksize(oracle):
    for i in range(1, 64):
        s = 'a' * i * 4
        cypher = oracle(s)
        if cypher[:i] == cyper[i:i*2] && cypher[i*2:i*3] == cypher[i*3:i*4]: return i
