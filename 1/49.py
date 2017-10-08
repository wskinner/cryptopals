from util import *

def cbc_mac(msg, key, iv, bs=16):
    # If they're using CBC-MAC, surely they are not padding their messages :)
    # This makes part 2 a little simpler
    ct = cbc_encrypt_nopad(msg, key, iv, bs)
    return ct[-bs:]

class API(object):
    
    def __init__(self, key, bs=16):
        self.key = key
        self.bs = bs
        self.accounts = {}

    def add_accounts(self, accounts):
        for k, v in accounts.iteritems():
            self.accounts[k] = v
        print self.accounts

    def get_balance(self, acct):
        return self.accounts[acct]

    def handle(self, payload):
        '''
        payload = message || IV || MAC
        msg looks like: from=from_id&to=to_id&amount=amount
        '''
        bs = self.bs
        msg = payload[:-bs*2]
        iv = payload[-bs*2:-bs]
        mac = payload[-bs:]
        
        my_mac = cbc_mac(msg, self.key, iv, bs)
        if mac == my_mac:
            deets = parse_kv(msg)
            # valid signature
            self.apply_txn(deets['from'], deets['to'], int(deets['amount']))
            return 'ok'
        else:
            return 'invalid signature'

    def handle2(self, payload):
        '''
        payload = message || mac
        '''
        iv = '\x00' * 16
        bs = self.bs
        msg = payload[:-bs]
        mac = payload[-bs:]

        my_mac = cbc_mac(msg, self.key, iv, bs)
        if mac == my_mac:
            # valid signature
            deets = parse_kv(msg)
            frm = deets['from']
            for to, amt in map(lambda x: x.split(':'), deets['tx_list'].split(';')):
                print 'frm to amt', frm, to, amt
                self.apply_txn(frm, to, int(amt))
            return 'ok'
        else:
            return 'invalid signature'

    def apply_txn(self, frm, to, amt):
        self.accounts[frm] -= amt
        self.accounts[to] += amt


class Client(object):
    '''
    Represents a web client controlled by the attacker. 
    I'm not quite clear what scenario this is supposed to represent, where the
    attacker controls the iv but not the secret key.
    '''

    def __init__(self, api, key):
        self.api = api
        self.key = key

    def send(self, msg, iv):
        '''
        Assume msg is well formed and clean.
        '''
        mac = cbc_mac(msg, self.key, iv)
        payload = msg + iv + mac
        resp = self.api.handle(payload)
        return payload, resp

    def send2(self, msg):
        '''
        Assume msg is well formed and clean.
        '''
        iv = '\x00' * 16
        mac = cbc_mac(msg, self.key, iv)
        payload = msg + mac
        resp = self.api.handle2(payload)
        return payload, resp

def forge_transfer():
    # Attacker owns accounts 1 and 2
    # We want to steal from account 3
    # iv[5] xor '1' == x
    # need b s.t. b xor '3' == x
    # x = iv[5] xor '1'
    # x = b xor '3'
    # b = x xor '3'
    # b = iv[5] xor '1' xor '3'
    key = keygen()
    api = API(key)
    api.add_accounts({'1': 1000, '2': 1000, '3':10000000000})
    client = Client(api, key)
    msg1 = 'from=1&to=2&gr=a&amount=10000000'
    msg2 = 'from=3&to=2&gr=a&amount=10000000'
    iv = keygen()
    b = xor_byte_strings('3', xor_byte_strings(iv[5], '1'))
    assert ord(b) ^ ord('3') == ord(iv[5]) ^ ord('1')
    iv2 = iv[:5] + b + iv[6:]
    
    payload, resp = client.send(msg1, iv)
    assert resp == 'ok'

    payload2, resp2 = client.send(msg2, iv2)
    assert resp2 == 'ok'

def forge_transfer2():
    # Attacker owns accounts 1 and 2.
    key = keygen()
    api = API(key)
    api.add_accounts({'1': 1000, '2': 1000, '3': 10000000000, '4': 50000})
    client = Client(api, key)
    print api.accounts
    
    assert api.get_balance('3') == 10000000000
    msg1 = 'from=3&nnnnnn=nnnn&tx_list=4:100'
    payload, resp = client.send2(msg1)
    assert resp == 'ok' and api.get_balance('3') == 10000000000 - 100 and (
            api.get_balance('4') == 50000 + 100)
    mac = payload[-16:]
    print api.accounts

    # want to add ';1:1000000'
    my_msg = ';1:1000000;2:900'
    new_msg = msg1 + my_msg
    new_mac = cbc_mac(my_msg, key, mac)
    resp = api.handle2(new_msg + new_mac)
    print api.accounts
    assert resp == 'ok' and api.get_balance('3') == 9998998900 and api.get_balance('1') == 1001000

forge_transfer()
forge_transfer2()
