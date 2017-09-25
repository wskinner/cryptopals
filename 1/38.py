import hashlib, hmac
from util import modexp
from srp import *
import sys

# Method:
#
# We have:
# B = g**b % n
# x = SHA256(salt|password)
# S = B**(a + ux) % N
# K = SHA256(S)
# HMAC-SHA256(K, salt)
# If we send the client B = g, u = 1, then because 
# A = g**a
# they will be computing, 
# S = B**(a + ux) == A**(a + ux) == A * A**x
# So we can brute force the space by Trying values of x until we find x such that
# HMAC-SHA256(SHA256(A * A**SHA256(salt|x)), salt) == S

def try_login(server, client):
    salt, B, u = server.rcv_msg1(client.email, client.A)
    mac = client.rcv_msg2(salt, B, u)
    ok = server.rcv_msg3(mac)
    return ok == 'OK'

# If we inject 0 as A, the server will generate K = SHA256(S) = SHA256(0).
# So we can just generate HMAC-SHA256(0, salt) and send it to the server.
if __name__ == '__main__':
    username = sys.argv[1]
    password = sys.argv[2]
    
    if len(sys.argv) > 3:
        server = SimpleSRPMITM()
    else:
        server = SimpleSRPServer(username, password)

    while True:
        client_password = raw_input('Enter password for user ' + username + ': ').strip()
        #inject_A = int(raw_input('Enter parameter A to inject: '), 16)
        client = SimpleSRPClient(username, client_password)
        if try_login(server, client):
            print 'Logged in!'
            exit()
        else:
            print 'Incorrect username or password.'
