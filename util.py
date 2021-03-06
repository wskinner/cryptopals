from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto import Random
import random
import struct
import bitarray
import pickle

def padding_length(st):
    try:
        last = ord(st[-1])
        if last == 0: return False
        if last > 16: return False
        for i in range(len(st) - last, len(st)):
            assert ord(st[i]) == last
        return last
    except:
        return -1

def padding_valid(st):
    try:
        last = ord(st[-1])
        if last == 0: return False
        if last > 16: return False
        for i in range(len(st) - last, len(st)):
            assert ord(st[i]) == last
        return True
    except:
        return False

def strip_padding(st):
    l = padding_length(st)
    return st[: -l]
    raise Exception('Invalid Padding')

# Given something like 'foo=bar&baz=qux&zap=zazzle'
# return a dictionary like {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
def parse_kv(st):
    pairs = st.strip().split('&')
    d = {}
    for p in pairs:
        kv = p.split('=')
        d[kv[0]] = kv[1]
    return d

def encode_kv(d):
    st = 'email=' + d['email'] + '&uid=' + d['uid'] + '&role=' + d['role']
    return st

email_to_id = {}
next_id = 0
# Profile IDs last the duration of an interpreter session
def profile_for(email):
    global next_id
    email = email.replace('=', '').replace('&', '')
    if email in email_to_id:
        return email_to_id[email]
    else:
        email_to_id[email] = next_id
        next_id += 1
    d = {'email': email, 'uid': str(email_to_id[email]), 'role': 'user'}
    return encode_kv(d)

# Encode a string as a number
def naive_str_to_num(st):
    padded = st.encode('hex')
    return int(padded, 16)

# Decode the string that was encoded with encode_hex
def naive_num_to_str(num):
    hexst = hex(num).replace('L', '')
    chars = []
    for i in xrange(2, len(hexst), 2):
        c = chr(int(hexst[i:i+2], 16))
        chars.append(c)
    return ''.join(chars)

# This and the below function are as specified by the DSA spec.
def str_to_num(st):
    ba = bitarray.bitarray()
    ba.frombytes(st)
    total = 0
    n = len(st) * 8 - 1
    for b in ba:
        if b: total += 2**n
        n -= 1
    
    return total

def num_to_str(num, n_bits):
    if num == 0: 
        return (n_bits / 8) * '\x00'
    n_bits = max(n_bits, 8)
    mask = 0xff << n_bits - 8
    chars = []
    shift_bits = n_bits - 8
    while mask >= 0xff:
        b = (num & mask) >> shift_bits
        chars.append(chr(b))
        mask = mask >> 8
        shift_bits -= 8

    return ''.join(chars)

def str_to_nums(st):
    return map(ord, st)

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
    if padding_needed == 0: padding_needed = 16
    return data + chr(padding_needed) * padding_needed

# AES-128 encrypt with cbc mode 
# Ci = AES(Pi xor Ci-1)
def cbc_decrypt(data, key, iv, bs=16):
    aes = AES.new(key, AES.MODE_ECB)
    plain_blocks = []
    prev_cipher_block = iv
    for i in range(0, len(data), bs):
        block = data[i:i+bs]
        plain = xor_byte_strings(aes.decrypt(block), prev_cipher_block)
        prev_cipher_block = block
        plain_blocks.append(plain)

    return ''.join(plain_blocks)

def ecb_encrypt(data, key, bs=16):
    aes = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(data)
    return aes.encrypt(padded)

def ecb_decrypt(ciphertext, key, bs=16):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(ciphertext)

def cbc_encrypt(data, key, iv, bs=16):
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(data)
    return aes.encrypt(padded)

def cbc_encrypt_nopad(data, key, iv, bs=16):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(data)

def make_ctr_nonce(i):
    nonce_bytes = chr(0) * 8
    if i < (2**32 - 1):
        nonce_bytes += ''.join(reversed(struct.pack('>Q', i)))
    else:
        # TODO
        raise Exception("that's a big nonce...")
    return nonce_bytes

def ctr_encrypt(data, key, nonce, bs=16):
    aes = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), bs):
        nonce_bytes = make_ctr_nonce(nonce)
        block = data[i:i+bs]
        yield xor_byte_strings(aes.encrypt(nonce_bytes), block)
        nonce += 1

def ctr_decrypt(data, key, nonce, bs=16):
    return ctr_encrypt(data, key, nonce, bs)

def keygen(bs=16, seed=None):
    if seed is not None:
        random.seed(seed)
        return ''.join([chr(random.choice(range(256))) for i in range(bs)])
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
        if cypher[:i] == cyper[i:i*2] and cypher[i*2:i*3] == cypher[i*3:i*4]: return i

def stringify_stream(gen):
    return ''.join([x for x in gen])

def get_blocks(data, bs=16):
    return [data[i:i+bs] for i in range(0, len(data), bs)]

class MersenneTwister:

    def __init__(self, seed):
        # length n
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = self._int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def randint(self):
        return self.extract_number()

    def extract_number(self):
        if self.index >= 624:
            self.twist()
        y = self.mt[self.index]

        y1 = y ^ (y >> 11)
        y2 = y1 ^ ((y1 << 7) & 2636928640)
        y3 = y2 ^ ((y2 << 15) & 4022730752)
        y4 = y3 ^ (y3 >> 18)

        self.index += 1

        return self._int32(y4)

    def twist(self):
        for i in range(624):
            y = self._int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i+1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df

            self.index = 0

    def _int32(self, x):
        return int(0xFFFFFFFF & x)

def modexp(x, e, m):
    X = x
    E = e
    Y = 1
    while E > 0:
        if E % 2 == 0:
            X = (X * X) % m
            E = E/2
        else:
            Y = (X * Y) % m
            E = E - 1
    return Y

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
    if gcd != 1:
        raise Exception('multiplicative inverse does not exist for a=%d, m=%d' % (a, m))
    result = coefficients[0] % m
    return result

# Multiply d by the multiplicate inverse of x, mod m
def modinv(x, d, m):
    inv = invmod(x, m)
    return (d * inv) % m

def cube_root(x, closest=False):
    '''
    Uses binary search to find the cube root of a large integer. 
    Assumes the root actually exists.
    '''
    mn = 0
    mx = x
    mid = x / 2
    while True:
        cube = mid**3
        #print 'diff, mn, mid, mx', x - cube, mn, mid, mx
        if cube > x:
            # need to reduce base
            if mx - mn == 1:
                if mn**3 == x:
                    return mn
                else:
                    if closest:
                        return mid
                    raise Exception('Number is not a perfect cube')
            else:
                mx = mid
        elif cube < x:
            if mx - mn == 1:
                if mx**3 == x: 
                    return mx
                else:
                    if closest:
                        return mid
                    raise Exception('Number is not a perfect cube')
                mid = mx
            else:
                mn = mid
        else:
            return mid

        mid = (mx + mn) // 2

def cbc_mac(msg, key, iv, bs=16):
    # If they're using CBC-MAC, surely they are not padding their messages :)
    # This makes part 2 a little simpler
    ct = cbc_encrypt_nopad(msg, key, iv, bs)
    return ct[-bs:]

def generate_strings(byte_length, offset=0):
    '''
    Lazily enumerate all the strings of exactly byte_length bytes
    '''
    end = 2**(byte_length * 8)
    assert offset < end
    for num in xrange(offset, end):
        yield num_to_str(num, byte_length * 8)

class Serializable(object):
    def serialize(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self, f)
    
    @staticmethod
    def deserialize(filename):
        with open(filename, 'rb') as f:
            return pickle.load(f)

def single_block_collision(hash_factory, initial_state1, initial_state2, blocksize):
    for i, s1 in enumerate(generate_strings(blocksize)):
        for s2 in generate_strings(blocksize, i):
            h1 = hash_factory(h=initial_state1).update(s1).digest()
            h2 = hash_factory(h=initial_state2).update(s2).digest()
            if h2 == h1:
                return {
                        's1': s1, 
                        's2': s2,
                        'initial_state1': initial_state1,
                        'initial_state2': initial_state2,
                        'final_state': h1
                        }
