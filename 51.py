from util import *
import zlib
import string

'''
The session cookie is a 32 byte base64 encoded string, so our alphabet is [a-zA-Z0-9/+=

Strategy:
For CTR mode, we can try to crack each character one at a time by trying all possible 
characters from the alphabet and then picking the one that resulted in the longest
payload length. If two or more characters result in the same payload length, we
pick a new random suffix pad and try again. This works because the contents of the 
random suffix pad affect compressed size. Eventually we should find one that pushes
the compressed size across the block boundary.

The above does not work for CBC mode. The reason is that compression occurs before
encryption, and in most cases the result of a one byte difference in the compressed
size will simply result in one more byte of padding being used. The exception is 
when the compressed data fully filled a block. That would mean that a full block of
16 padding bytes was appended. If we then reduce the size of the compressed block by
one byte, only a single 01 padding byte will be used, so the size of the encrypted
payload will be less 16 bytes. We need to add an extra step to discover the compressed 
data length. We can do this by adding one byte at a time to our payload, and noticing
when the encrypted size jumps by 16. At this point we will know that our compressed
payload (before encryption) aligns to the block size.
'''

class CompressionOracle(object):

    def __init__(self, sessionid, mode='ctr'):
        self.sessionid = sessionid
        self.mode = mode

    def format_request(self, P):
        fmt = '''POST / HTTP/1.1
        Host: hapless.com
        Cookie: sessionid=%s
        Content-Length: %d
        %s''' % (self.sessionid, len(P), P)
        return fmt

    def encrypt(self, data, key):
        if self.mode == 'ctr':
            encrypted = stringify_stream(ctr_encrypt(data, key, 0))
        elif self.mode == 'cbc':
            iv = keygen()
            encrypted = cbc_encrypt(data, key, iv)
        else:
            raise Exception('Unsupported cipher mode "%s"' % self.mode)
        return encrypted

    def check(self, P):
        formatted = self.format_request(P)
        compressed = zlib.compress(formatted)
        key = keygen()
        encrypted = self.encrypt(compressed, key)

        return len(encrypted)

class CrackCompressionLeak(object):

    def __init__(self, oracle):
        self.oracle = oracle

    def guess(self, guess, times=1):
        length = self.oracle.check(guess * times)
        fmt = 'Guessing "%s" * %d, the oracle returns %d\n' % (guess, times, length)
        print fmt
    
    def crack_ctr(self):
        '''
        Crack one character at a time
        '''
        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/='
        fmt = 'Cookie: sessionid=%s'
        sofar = ''
        for i in xrange(44):
            print '------------- %s -------------' % sofar
            top10 = None
            while top10 is None or top10[0][0] == top10[1][0]:
                counts = []
                randomid = keygen(44 - len(sofar)).encode('base64')[-1]
                for c in alphabet:
                    prefix = sofar + c
                    payload = fmt % (prefix + randomid[len(prefix):])
                    counts.append((self.oracle.check(payload), c))
                counts = sorted(counts)
                it = iter(counts)
                top10 = [next(it) for i in range(10)]
                print top10
                
            sofar += top10[0][1]
        return sofar

    def make_pad(self, sofar):
        mn = 2**16
        mn_length = 2**16
        
        randomid = keygen(32).encode('base64')[:-1][len(sofar):]
        fmt = '%sCookie: sessionid=%s'
        pad = ''
        for i in range(-1, 16):
            payload = fmt % (pad, sofar + randomid)
            length = self.oracle.check(payload)
            print i, len(payload), length
            if length <= mn_length:
                mn_length = length
                mn = i
            elif i == 0:
                print 'i==0', len(randomid), "%s" % pad.encode('hex')
                return pad
            else:
                print 'i==' + str(i), len(randomid), "%s" % pad.encode('hex')
                return pad[:-1]

            # Use bytes that do not appear in the unencrypted message.
            if i >= 0: pad += chr(128 + i)


    def crack_cbc(self):
        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/='
        fmt = '%sCookie: sessionid=%s'
        sofar = ''
        for i in xrange(44):
            print '------------- %s -------------' % sofar
            pad = self.make_pad(sofar)
            suffix_bytes_start = len(sofar)
            if pad is None:
                suffix_bytes_start += 1
                pad = ''
            top10 = None
            cnt = 0
            while top10 is None or top10[0][0] == top10[1][0]:
                # This is necessary because the guess we make for needed padding
                # is just a guess. Sometimes using that pad will not result in a
                # separation between guessing the correct character and an 
                # incorrect one. If we notice this happening, we add an additional 
                # byte of padding and try again, hoping this time the correct guess 
                # will push us past the byte boundary. Ugly and slow but it works.
                if cnt > 0 and cnt % 256 == 0:
                    suffix_bytes_start -= 1
                    print 'Decremented suffix_bytes_start', suffix_bytes_start
                counts = []

                randomid = keygen(32).encode('base64')[:-1][suffix_bytes_start:]
                for c in alphabet:
                    prefix = sofar + c
                    payload = fmt % (pad, prefix + randomid)
                    counts.append((self.oracle.check(payload), c))
                counts = sorted(counts)
                it = iter(counts)
                top10 = [next(it) for i in range(10)]
                #print top10
                cnt += 1
                
            sofar += top10[0][1]
        return sofar


def test_ctr():
    # Just making sure my CTR implementation is not doing anything funny with 
    # padding
    msg = 7 * '\xff'
    key = keygen()
    ct = stringify_stream(ctr_encrypt(msg, key, 0))
    assert len(ct) == len(msg)

    msg = 17 * '\xff'
    key = keygen()
    ct = stringify_stream(ctr_encrypt(msg, key, 0))
    assert len(ct) == len(msg)

    msg = 32 * '\xff'
    key = keygen()
    ct = stringify_stream(ctr_encrypt(msg, key, 0))
    assert len(ct) == len(msg)

def test_guesses(mode='ctr'):
    sessionid = 'XUEs+IN0T+aSt/yD5BSIfNY2+ifAyZoMO3Pj4Xm6l1s='
    randomid = 'BYHt/c2Yyp30IObhSLQg/BOWi9CPRADPH2y1r5T9M2A='
    oracle = CompressionOracle(sessionid, mode)
    cracker = CrackCompressionLeak(oracle)

    for i in [1, 8]:
        print '---------------Multiplying guess by %d--------------' % i
        print 'Correct session id'
        cracker.guess(sessionid, times=i)

        print 'Correct session id with prefix'
        cracker.guess('Cookie: sessionid=' + sessionid, times=i)

        print 'Correct prefix with 32 random bytes'
        cracker.guess('Cookie: sessionid=' + randomid, times=i)

        print 'Empty'
        cracker.guess('', times=i)

        print '32 As'
        cracker.guess('A' * 32, times=i)

        print '32 Bs'
        cracker.guess('B' * 32, times=i)

        print 'Correct 1 prefix'
        cracker.guess('Cookie: sessionid=X', times=i)

        print 'Correct 2 prefix '
        cracker.guess('Cookie: sessionid=XU', times=i)
        
        print 'Cookie: sessionid='
        cracker.guess('Cookie: sessionid=', times=i)

def crack_ctr():
    print 'Cracking CTR mode'
    cracker = CrackCompressionLeak(CompressionOracle(secret))
    guess = cracker.crack_ctr()
    if guess == secret:
        print 'Guessed session id!', guess
    else:
        print "Didn't guess session id :( Best guess was", guess

def crack_cbc():
    print 'Cracking CBC mode'
    cracker = CrackCompressionLeak(CompressionOracle(secret, mode='cbc'))
    guess = cracker.crack_cbc()
    if guess == secret:
        print 'Guessed session id!', guess
    else:
        print "Didn't guess session id :( Best guess was", guess


if __name__ == '__main__':
    secret = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
    test_ctr()
    #test_guesses(mode='cbc')
    crack_ctr()
    crack_cbc()
