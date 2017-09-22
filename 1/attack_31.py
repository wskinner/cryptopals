import requests
import time

# Method:
# We will guess the hmac one byte at a time by checking all possible first bytes, 
# and choosing the one where the server took the longest to respond, then all the
# second bytes, and so on.

def current_millis():
    return int(round(time.time() * 1000))

if __name__ == '__main__':
    file = 'Ice Ice Baby'
    url = 'http://localhost:8080/test'
    status_code = 500
    known_prefix = ''
    while True:
        print 'so far', known_prefix.encode('hex')
        max_time = -1
        guess = ''
        times = {}
        for i in range(256):
            sig = known_prefix + chr(i)
            payload = {'file': file, 'signature': sig.encode('hex')}
            start = current_millis()
            resp = requests.get(url, params=payload, headers={'Content-Type': 'text/html; charset=utf-8'})
            if resp.status_code == 200:
                print 'Cracked!', payload
                exit()
            end = current_millis()
            elapsed = end - start
            if elapsed > max_time:
                guess = chr(i)
                max_time = elapsed
            times[sig] = elapsed
        print [i for i in sorted(times.iteritems(), key=lambda (k,v): (-v,k))][:5]
        known_prefix += guess
        
