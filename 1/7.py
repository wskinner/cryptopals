from Crypto.Cipher import AES

key = 'YELLOW SUBMARINE'

aes = AES.new(key, AES.MODE_ECB)
with open('7.txt') as f:
    data = f.read().strip().decode('base64')
    print aes.decrypt(data)
