from util import *
import zlib
import string

'''
The session cookie is a 32 byte base64 encoded string, so our alphabet is [a-zA-Z0-9/+=
Strategy:
'''

class CompressionOracle(object):

    def __init__(self, sessionid):
        self.sessionid = sessionid

    def format_request(self, P):
        fmt = '''POST / HTTP/1.1
        Host: hapless.com
        Cookie: sessionid=%s
        Content-Length: %d
        %s''' % (self.sessionid, len(P), P)
        return fmt

    def check(self, P):
        formatted = self.format_request(P)
        compressed = zlib.compress(formatted)
        key = keygen()
        encrypted = stringify_stream(ctr_encrypt(compressed, key, 0))

        return len(encrypted)

class CrackCompressionLeak(object):

    def __init__(self, oracle):
        self.oracle = oracle

    def guess(self, guess, times=1):
        length = self.oracle.check(guess * times)
        fmt = 'Guessing "%s" * %d, the oracle returns %d\n' % (guess, times, length)
        print fmt
    
    def crack(self):
        '''
        Crack one character at a time
        '''
        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/='
        fmt = 'Cookie: sessionid=%s'
        sofar = ''
        for i in xrange(44):
            print '------------- %s -------------' % sofar
            counts = []
            top10 = None
            while top10 is None or top10[0][0] == top10[1][0]:
                randomid = keygen(44 - len(sofar)).encode('base64')[-1]
                for c in alphabet:
                    prefix = sofar + c
                    payload = fmt % (prefix + randomid[len(prefix):])
                    counts.append((self.oracle.check(payload), c))
                counts = sorted(counts)
                it = iter(counts)
                top10 = [next(it) for i in range(10)]
                
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

def test_guesses():
    sessionid = 'XUEs+IN0T+aSt/yD5BSIfNY2+ifAyZoMO3Pj4Xm6l1s='
    randomid = 'BYHt/c2Yyp30IObhSLQg/BOWi9CPRADPH2y1r5T9M2A='
    oracle = CompressionOracle(sessionid)
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

if __name__ == '__main__':
    secret = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
    test_ctr()
    #test_guesses()
    cracker = CrackCompressionLeak(CompressionOracle(secret))
    guess = cracker.crack()
    if guess == secret:
        print 'Guessed session id!', guess
    else:
        print "Didn't guess session id :( Best guess was", guess

