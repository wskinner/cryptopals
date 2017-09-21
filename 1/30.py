from md4 import MD4
import struct

class MD4Mac:
    def __init__(self, key):
        self.key = key
    
    def sign(self, msg):
        md4 = MD4()
        digest = md4.update(key+msg).digest()
        return digest

    def validate(self, msg, mac):
        return self.sign(msg) == mac

def test():
    msg = 'hello'
    print 'Padding', md_padding(msg)
    print Sha1Hash().update(msg).hexdigest()

    msg = 'Ice Ice, Baby'
    print 'Padding', md_padding(msg)
    print Sha1Hash().update(msg).hexdigest()

def test2():
    sha = Sha1Hash()
    msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    sha.update(msg)
    d = sha.digest()
    length = sha._message_byte_length # wrong!
    sha2 = Sha1Hash(d, length)
    print 'sha2._h', sha2._h
    assert sha2._h == sha._h

# The reason we need to use the exact padding bytes is because the registers we
# are going to inject contain the hash state after hashing key || message || padding.
# So the final 
if __name__ == '__main__':
    #test2()
    #exit()

    key = 'yellow submarine'
    mac = MD4Mac(key)
    msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    output_mac = mac.sign(msg)

    evil = ';admin=true'
    # my_mac is the sha1 hash of key || msg || glue_padding || evil
    # we need to try all the possible key lengths to figure out which amount of
    # glue padding is in there.

    for i in range(32):
        pad = MD4.get_padding(len(msg) + i)
        mymd4 = MD4(digest=output_mac, length=i + len(msg) + len(pad))
        mymd4.update(evil)
        my_mac = mymd4.digest()
        full_msg = msg + pad + evil
        if mac.validate(full_msg, my_mac):
            print 'Forged message', my_mac.encode('hex'), 'key length = ', i
