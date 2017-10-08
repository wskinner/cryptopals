import hashlib
import sha1
from util import keygen

def authenticate(key, msg):
    return sha1.Sha1Hash().update(key + msg).digest()


if __name__ == '__main__':
    sha = sha1.Sha1Hash().update('hello')
    print 'my implementation', sha.hexdigest()
    print 'expected', hashlib.sha1('hello').hexdigest()
    
    key = keygen()
    print authenticate(key, 'oh my gourd')
