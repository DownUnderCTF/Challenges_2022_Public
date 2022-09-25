from pwn import *

def oracle(x):
    conn.sendlineafter(b'> ', str(x).encode())
    o = conn.recvline().decode()
    return '>:(' in o

conn = remote('0.0.0.0', 1337)

U = 10**4300
FLAG_BITS = 1024

lower = U//2**FLAG_BITS
upper = U
for _ in range(1024):
    middle = (upper + lower) // 2
    if oracle(middle):
        upper = middle - 1
    else:
        lower = middle + 1

n = middle
f = U//n + 1

print(f.to_bytes(128, 'big').strip(b'\x00').decode())
