from srp import *
def test():
    client = SRPClient('will@example.com', 'not a terribly strong password')
    server = SRPServer('will@example.com', 'not a terribly strong password')
    salt, B = server.rcv_msg1(client.email, client.A)
    mac = client.rcv_msg2(salt, B)
    ok = server.rcv_msg3(mac)
    assert ok == 'OK'

if __name__ == '__main__':
    test()
