import requests
import time
from collections import defaultdict

# Method:
# We will guess the hmac one byte at a time by checking all possible first bytes, 
# and choosing the one where the server took the longest to respond, then all the
# second bytes, and so on. This time, the timing difference is smaller. We will
# try making more requests and averaging the results to reduce variance from other 
# factors.

def current_millis():
    return int(round(time.time() * 1000))

if __name__ == '__main__':
    file = 'Ice Ice Baby'
    url = 'http://localhost:8080/test'
    known_prefix = ''
    while True:
        print 'so far', known_prefix.encode('hex')
        max_time = -1
        times = defaultdict(list)
        for i in range(10):
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
                times[chr(i)].append(elapsed)
        
        trimmed = {}
        for guess, obs in times.iteritems():
            trimmed[guess] = sum([i for i in sorted(obs)][:-2])
        best_guess = [i for i in sorted(trimmed.items(), key=lambda (k, v): (-v, k))][:3]
        print best_guess

        known_prefix += best_guess[0][0]
        
