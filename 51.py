from util import *
import zlib

def format_request(P):
    fmt = '''POST / HTTP/1.1
    Host: hapless.com
    Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
    Content-Length: %d
    %s''' % (len(P), P)

def compression_oracle(P):
    formatted = format_request(P)
    compressed = zlib.compress(formatted)
    key = keygen()
    encrypted = stringify_stream(ctr_encrypt(compressed, key, 0))

    return len(encrypted)


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

if __name__ == '__main__':
    test_ctr()
