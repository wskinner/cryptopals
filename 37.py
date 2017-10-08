from srp import *
import sys
import hashlib, hmac

def try_login(server, client, A):
    salt, B = server.rcv_msg1(client.email, A)
    sha = hashlib.sha256()
    sha.update(hex(0L))
    K = sha.digest()
    mac = hmac.new(K, hex(salt), hashlib.sha256).digest()

    ok = server.rcv_msg3(mac)
    return ok == 'OK'

# If we inject 0 as A, the server will generate K = SHA256(S) = SHA256(0).
# So we can just generate HMAC-SHA256(0, salt) and send it to the server.
if __name__ == '__main__':
    username = sys.argv[1]
    password = sys.argv[2]

    server = SRPServer(username, password)

    while True:
        client_password = raw_input('Enter password for user ' + username + ': ')
        inject_A = int(raw_input('Enter parameter A to inject: '), 16)
        client = SRPClient(username, client_password)
        if try_login(server, client, inject_A):
            print 'Logged in!'
            exit()
        else:
            print 'Incorrect username or password.'
