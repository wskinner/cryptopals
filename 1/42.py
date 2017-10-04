from hashlib import md5
import ujson as json
from rsa import *
from util import cube_root
import struct
import re

# Digital signature implementation based on PKCS1.5
# Hardcoded to use md5
# I'm using json instead of ASN.1 because specifically using ASN.1 as the DDL
# is not necessary to this attack, and ASN.1 is a pain in the ass
class RSASignature:
    '''
    The signature process consists of four steps: 

    message digesting, 
    data encoding, 
    RSA encryption, 
    octet-string-to-bit-string conversion.

    The input to the signature process shall be an octet string M, the
    message; and a signer's private key. The output from the signature
    process shall be a bit string S, the signature.

    From Phinney's description of the attack,
    Some implementations apparently remove the PKCS-1 padding by
    looking for the high bytes of 0 and 1, then the 0xFF bytes, then
    the zero byte; and then they start parsing the ASN.1 data and hash.

    The standard requires the signature block be formatted as
    00 01 FF FF FF ... FF 00  ASN.1  HASH
    with the number of FF blocks chosen to fill a whole block.
    '''

    def __init__(self, rsa):
        self.rsa = rsa
        self.digest = md5
        self.padding_re = re.compile('\xff\x01\xff+\x00(.*)')

    def asn_enc(self):
        info = {'algo': 'MD5'}
        return json.dumps(info)

    def asn_dec(self, enc):
        return json.loads(enc)

    def pad(self, info, msg_digest):
        bs = self.rsa.n_bits // 8
        padding_needed = bs - len(info) - len(msg_digest) - 3
        payload = '\xff\x01%s\x00%s%s' % ('\xff' * padding_needed, info, msg_digest)
        return payload

    # strip the padding from payload, returning the remainder of the payload 
    # after the padding. If padding is invalid, returns None
    def parse_pad(self, payload):
        m = self.padding_re.match(payload)
        if not m:
            return None
        return m.group(1)

    def parse_asn(self, payload):
        if payload[0] != '{':
            return None
        count = 1
        i = 1
        while count > 0:
            if payload[i] == '{': count += 1
            if payload[i] == '}': count -= 1
            i += 1
        return payload[i:]

    def parse_hash(self, payload):
        # 128 bit hash, hardcoded for md5
        hashlen = 16
        return payload[:16]

    def sign(self, msg):
        hsh = self.digest()
        hsh.update(msg)
        msg_digest = hsh.digest()

        ser = self.asn_enc()

        # I changed the first byte from the specified 00 to ff. This is because the naive
        # way that my implementation encodes strings to numbers cannot tolerate leading zeros.
        # Probably not worth fixing now, hence this hack
        payload = self.pad(ser, msg_digest)
        enc_payload = self.rsa.reverse_encrypt(payload)
        return enc_payload
    
    def validate(self, signature, msg):
        dec = self.rsa.reverse_decrypt(signature)
        bs = self.rsa.n_bits // 8
        if len(dec) != bs:
            print 'Invalid signature length.'
            return False

        # Hardcoded for md5
        digest_bytes = 16 
        digest = dec[-16:]
        
        digester = self.digest()
        digester.update(msg)
        expected_digest = digester.digest()
        return expected_digest == digest

    # Broken validator that does not check the length of the signature block
    def validate_broken(self, signature, msg):
        dec = self.rsa.reverse_decrypt(signature)
        bs = self.rsa.n_bits // 8
        
        digest = self.parse_hash(self.parse_asn(self.parse_pad(dec)))
        
        digester = self.digest()
        digester.update(msg)

        expected_digest = digester.digest()
        return expected_digest == digest


def test_signature():
    msg = 'Cooking MCs like a pound of bacon'
    himom = 'hi mom'
    rsa = RSA.new(1024)
    signer = RSASignature(rsa)
    signature = signer.sign(msg)
    assert signer.validate(signature, msg)
    assert not signer.validate(signature, msg + 'naise')
    assert not signer.validate(signature, himom)


def bleichenbacher():
    himom = 'hi mom'
    rsa = RSA.new(1024)
    signer = RSASignature(rsa)
    
    info = signer.asn_enc()
    bs = rsa.n_bits / 8

    digester = md5()
    digester.update(himom)
    msg_digest = digester.digest()
    
    padding_needed = bs - len(info) - len(msg_digest) - 4
    padding = '\x00' * padding_needed
    payload = '\xff\x01\xff\x00%s%s%s' % (info, msg_digest, padding)
    
    num_payload = str_to_num(payload)
    closest_cube = cube_root(num_payload, closest=True)
    while closest_cube**3 < num_payload:
        closest_cube += 1
    diff = closest_cube**3 - num_payload
    np1 = num_payload + diff
    cube_payload = cube_root(np1)
    assert cube_payload**3 == np1
    assert signer.validate_broken(cube_payload, himom)
    print 'Successfully forged signature for', "'%s'" % himom

test_signature()
bleichenbacher()
