from util import pkcs7_pad

data = 'YELLOW SUBMARINE'
print data.encode('hex')
print pkcs7_pad(data, 20).encode('hex')
