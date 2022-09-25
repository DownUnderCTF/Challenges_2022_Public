import sys
sys.setrecursionlimit(2**22)

from hashlib import sha512
from json import loads
from base64 import b64decode

LOCK = loads(b64decode(open('./LOCK.b64', 'rb').read()).decode())
ct = bytes([62, 223, 233, 153, 37, 113, 79, 195, 9, 58, 83, 39, 245, 213, 253, 138, 225, 232, 123, 90, 8, 98, 105, 1, 31, 198, 67, 83, 41, 139, 118, 138, 252, 165, 214, 158, 116, 173, 174, 161, 6, 233, 37, 35, 86, 7, 108, 223, 97, 251, 2, 245, 129, 118, 227, 120, 26, 70, 40, 26, 183, 90, 172, 155])

def find_key(T, k, path=''):
    if T == k:
        return path
    if type(T) is list:
        for i, t in enumerate(T):
            r = find_key(t, k, path + '1'*i + '0')
            if r:
                return r

def check_key(h, k):
    T = LOCK
    idx = 0
    for i in h:
        if i == '1':
            idx += 1
        if i == '0':
            T = T[idx]
            idx = 0
    return T == k

key = ''
for k in range(1, 1338):
    h = find_key(LOCK, k)
    key += h
    assert check_key(h, k)

key = sha512(key.encode()).digest()
flag = bytes([a ^ b for a, b in zip(ct, key)])
print(flag.decode())
