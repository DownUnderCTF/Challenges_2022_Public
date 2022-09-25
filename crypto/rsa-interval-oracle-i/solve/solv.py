from pwn import *

def oracle_in_interval(lower, upper, c):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Lower bound: ', str(lower).encode())
    conn.sendlineafter(b'Upper bound: ', str(upper).encode())
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'queries: ', str(c).encode())
    r = int(conn.recvline().decode())
    return r == 0

# context.log_level = 'debug'
# conn = process('./rsa-interval-oracle-i.py')
conn = remote('0.0.0.0', 1337)

N = int(conn.recvline().decode())
secret_ct = int(conn.recvline().decode())

lower = 0
upper = N
while lower <= upper:
    middle = (upper + lower) // 2
    if oracle_in_interval(0, middle, secret_ct):
        upper = middle - 1
    else:
        lower = middle + 1

conn.sendlineafter(b'> ', b'3')
conn.sendlineafter(b'Enter secret: ', str(upper).encode())
print(conn.recvline().decode())
