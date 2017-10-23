import struct

class MD4(object):
    '''
    Implementation of MD4 according to https://tools.ietf.org/html/rfc1320
    '''

    def __init__(self):
        pass

    def pad(self, msg):
        '''
        Step 1.
        '''
        length_bytes = self.length(msg)
        bytes448 = 448 / 8
        bytes512 = 512 / 8
        mod512 = len(msg) % bytes512
        if mod512 == bytes448:
            padlength = bytes512
        elif mod512 > bytes448:
            padlength = bytes512 - (mod512 - bytes448)
        else:
            padlength = bytes448 - mod512

        pad = '\x80' + (padlength - 1) * '\x00'
        return msg + pad + length_bytes

    def length(self, msg):
        '''
        Step 2.
        '''
        return struct.pack('<Q', 8 * len(msg))

    def initialize_md(self):
        A = 0x67452301
        B = 0xefcdab89
        C = 0x98badcfe
        D = 0x10325476
        return A, B, C, D
    
    # The below auxilliary functions each take three 32 bit words and return a
    # single 32 bit word.

    def f(self, x, y, z):
        return (x & y) | (~x & z)

    def g(self, x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(self, x, y, z):
        return x ^ y ^ z

    def round1(self, a, b, c, d, k, s, X):
        '''
        perform a = (a + F(b,c,d) + X[k]) <<< s
        returns a
        '''
        return self.rotl((a + self.f(b, c, d) + X[k]), s)

    def round2(self, a, b, c, d, k, s, X):
        '''
        perform a = (a + G(b,c,d) + X[k] + 5A827999) <<< s.
        returns a
        '''
        return self.rotl(a + self.g(b, c, d) + X[k] + 0x5A827999, s)

    def round3(self, a, b, c, d, k, s, X):
        '''
        perform a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s.
        returns a
        '''
        return self.rotl(a + self.h(b, c, d) + X[k] + 0x6ED9EBA1, s)

    def digest(self, msg):
        self.initialize_md()
        M = self.pad(msg)
        
        A, B, C, D = self.initialize_md()

        # 1 word is 4 bytes
        # 1 block is 16 words, i.e. 512 bits
        # i is the block index.
        assert len(M) >= 64
        assert len(M) % 64 == 0
        for i in xrange(0, len(M) / 64):
            # X is the working block, indexed by 4 byte word
            block = M[i*64:i*64+64]
            assert len(block) == 64

            X = [struct.unpack('<I', block[j:j+4])[0] for j in xrange(0, 64, 4)]
            assert len(X) == 16
        
            AA = A
            BB = B
            CC = C
            DD = D

            ## Round 1
            A = self.round1(A, B, C, D, 0, 3, X)
            D = self.round1(D, A, B, C, 1, 7, X)
            C = self.round1(C, D, A, B, 2, 11, X)
            B = self.round1(B, C, D, A, 3, 19, X)

            A = self.round1(A, B, C, D, 4, 3, X)
            D = self.round1(D, A, B, C, 5, 7, X)
            C = self.round1(C, D, A, B, 6, 11, X)
            B = self.round1(B, C, D, A, 7, 19, X)

            A = self.round1(A, B, C, D, 8, 3, X)
            D = self.round1(D, A, B, C, 9, 7, X)
            C = self.round1(C, D, A, B, 10, 11, X)
            B = self.round1(B, C, D, A, 11, 19, X)

            A = self.round1(A, B, C, D, 12, 3, X)
            D = self.round1(D, A, B, C, 13, 7, X)
            C = self.round1(C, D, A, B, 14, 11, X)
            B = self.round1(B, C, D, A, 15, 19, X)

            ## Round 2
            A = self.round2(A, B, C, D, 0, 3, X)
            D = self.round2(D, A, B, C, 4, 5, X)
            C = self.round2(C, D, A, B, 8, 9, X)
            B = self.round2(B, C, D, A, 12, 13, X)

            A = self.round2(A, B, C, D, 1, 3, X)
            D = self.round2(D, A, B, C, 5, 5, X)
            C = self.round2(C, D, A, B, 9, 9, X)
            B = self.round2(B, C, D, A, 13, 13, X)

            A = self.round2(A, B, C, D, 2, 3, X)
            D = self.round2(D, A, B, C, 6, 5, X)
            C = self.round2(C, D, A, B, 10, 9, X)
            B = self.round2(B, C, D, A, 14, 13, X)

            A = self.round2(A, B, C, D, 3, 3, X)
            D = self.round2(D, A, B, C, 7, 5, X)
            C = self.round2(C, D, A, B, 11, 9, X)
            B = self.round2(B, C, D, A, 15, 13, X)

            ## Round 3
            A = self.round3(A, B, C, D, 0, 3, X)
            D = self.round3(D, A, B, C, 8, 9, X)
            C = self.round3(C, D, A, B, 4, 11, X)
            B = self.round3(B, C, D, A, 12, 15, X)

            A = self.round3(A, B, C, D, 2, 3, X)
            D = self.round3(D, A, B, C, 10, 9, X)
            C = self.round3(C, D, A, B, 6, 11, X)
            B = self.round3(B, C, D, A, 14, 15, X)

            A = self.round3(A, B, C, D, 1, 3, X)
            D = self.round3(D, A, B, C, 9, 9, X)
            C = self.round3(C, D, A, B, 5, 11, X)
            B = self.round3(B, C, D, A, 13, 15, X)

            A = self.round3(A, B, C, D, 3, 3, X)
            D = self.round3(D, A, B, C, 11, 9, X)
            C = self.round3(C, D, A, B, 7, 11, X)
            B = self.round3(B, C, D, A, 15, 15, X)
            
            mask_u32 = 0xFFFFFFFF
            A = (A + AA) & mask_u32
            B = (B + BB) & mask_u32
            C = (C + CC) & mask_u32
            D = (D + DD) & mask_u32
    
        '''
        From the spec:
        The message digest produced as output is A, B, C, D. That is, we
        begin with the low-order byte of A, and end with the high-order byte
        of D.
        '''
        a = struct.pack('<I', A)
        b = struct.pack('<I', B)
        c = struct.pack('<I', C)
        d = struct.pack('<I', D)
        return '%s%s%s%s' % (a, b, c, d)

    def hexdigest(self, msg):
        return self.digest(msg).encode('hex')

    @staticmethod
    def rotl(val, r_bits, max_bits=32):
        '''
        https://www.falatic.com/index.php/108/python-and-bitwise-rotation
        '''
        return (val << r_bits%max_bits) & (2**max_bits-1) | \
            ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def test_pad():
    md4 = MD4()

    # shorter than 56
    msg = 'hello'
    padded = md4.pad(msg)
    assert len(padded) == 64

    # equal to 56
    msg = 56 * '\x00'
    padded = md4.pad(msg)
    assert len(padded) == 128
    
    # longer than 56
    msg = 57 * '\x00'
    padded = md4.pad(msg)
    assert len(padded) == 128

def test_rotl():
    x = 0xffffffff
    for i in xrange(64):
        assert MD4.rotl(x, i) == x

    x = 0
    for i in xrange(64):
        assert MD4.rotl(x, i) == x
    
    x = 1
    for i in xrange(32):
        expected = 2**i
        assert MD4.rotl(x, i) == expected

def test_md4():
    '''
    Test the implementation using the test vectors from RFC1320
    '''
    print 'Testing the test vectors'
    assert MD4().hexdigest('') == '31d6cfe0d16ae931b73c59d7e0c089c0'
    assert MD4().hexdigest('a') == 'bde52cb31de33e46245e05fbdbd6fb24'
    assert MD4().hexdigest('abc') == 'a448017aaf21d8525fc10ae87aa6729d'
    assert MD4().hexdigest('message digest') == 'd9130a8164549fe818874806e1c7014b'
    assert MD4().hexdigest('abcdefghijklmnopqrstuvwxyz') == 'd79e1c308aa5bbcdeea8ed63df412da9'
    assert MD4().hexdigest('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') == '043f8582f241db351ce627e153e7f0e4'
    assert MD4().hexdigest('12345678901234567890123456789012345678901234567890123456789012345678901234567890') == 'e33b4ddc9c38f2199c3e7b164fcc0536'
    print 'All tests passed!'
    
if __name__ == '__main__':
    test_rotl()
    test_pad()
    test_md4()
