from util import *
from sha1 import Sha1Hash
import web
import time

class HMAC:
    def __init__(self, hsh_factory, key, bs=64):
        self.hsh_factory = hsh_factory
        if len(key) > bs:
            self.key = hsh_factory().update(key).digest()
        elif len(key) < bs:
            self.key = key + '\x00' * (bs - len(key))
        else:
            self.key = key
        opad = bs * '\x5c'
        self.okey_pad = xor_byte_strings(opad, self.key)
        ipad = bs * '\x36'
        self.ikey_pad = xor_byte_strings(ipad, self.key)

    def sign(self, msg):
        hsh1 = self.hsh_factory()
        hsh2 = self.hsh_factory()
        return hsh1.update(self.okey_pad + hsh2.update(self.ikey_pad + msg).digest()).digest()

def current_millis():
    return int(round(time.time() * 1000))

def insecure_compare(a, b):
    start_time = current_millis()
    for i in range(len(a)):
        if i >= len(b) or a[i] != b[i]: 
            print 'end compare', current_millis() - start_time, a[len(b) -1].encode('hex'), b[-1].encode('hex')
            return False
        time.sleep(.005)

    print 'end compare (returning true)', current_millis() - start_time
    return True

class Test:
    #key = keygen(64)
    key = 'yellow submarine'

    def __init__(self):
        self.hmac = HMAC(Sha1Hash, Test.key)

    def GET(self):
        start_time = current_millis()
        params = web.input()
        mac = self.hmac.sign(bytes(params['file']))
        candidate = bytes(params['signature']).decode('hex')
        valid = insecure_compare(mac, candidate)
        if valid:
            return 'valid'
        else:
            print 'returning', current_millis() - start_time, mac[len(candidate) -1].encode('hex'), candidate[-1].encode('hex')
            return web.internalerror('invalid')

def test():
    inputs = [
            'hello',
            'this is a test',
            '''The design of the HMAC specification was motivated by the existence of attacks on more trivial mechanisms for combining a key with a hash function. For example, one might assume the same security that HMAC provides could be achieved with'''
            ]
    
    key = 'yellow submarine'
    hmac = HMAC(Sha1Hash, key)
    for i in inputs:
        print i, hmac.sign(i).encode('hex')

#test()

urls = (
        '/test', 'Test'
        )

if __name__ == '__main__':
    #test()
    hmac = HMAC(Sha1Hash, Test.key)
    print 'actual mac', hmac.sign('Ice Ice Baby').encode('hex')
    app = web.application(urls, globals())
    app.run()
