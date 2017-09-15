from util import *
secret = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
key = 'YELLOW SUBMARINE'

if __name__ == '__main__':
    print ''.join([i for i in ctr_decrypt(secret.decode('base64'), key, 0)])
