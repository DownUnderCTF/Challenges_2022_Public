from pwn import *
from gmpy2 import c_div

QUERIES_USED = 0
MAX_QUERIES = 384

# https://www.iacr.org/archive/crypto2001/21390229.pdf
def manger(c, N, e, oracle, B):

    print('[*] starting step 1')
    queries_step1 = 0
    # f1 = 2
    f1 = 2**40
    while not oracle(f1, c, e, N):
        queries_step1 += 1
        f1 *= 2
    f12 = f1//2
    print(f'[*] step 1 finished in {queries_step1} queries. f1 = {f1}')

    print('[*] starting step 2')
    queries_step2 = 0
    f2 = (N+B)//B * f12
    while oracle(f2, c, e, N):
        queries_step2 += 1
        f2 += f12
    print(f'[*] step 2 finished in {queries_step2} queries. f2 = {f2}')

    print('[*] starting step 3')
    queries_step3 = 0
    mmin = c_div(N, f2)
    mmax = (N+B)//f2
    while mmax - mmin > 0:
        print('diff:', mmax-mmin)
        if QUERIES_USED >= MAX_QUERIES:
            print(mmin, mmax)
            break
        queries_step3 += 1
        ftmp = (2*B)//(mmax - mmin)
        i = c_div(ftmp * mmin, N)
        f3 = c_div(i*N, mmin)
        if oracle(f3, c, e, N):
            mmin = c_div(i*N+B, f3)
        else:
            mmax = (i*N+B)//f3
    print(f'[*] step 3 stopped after {queries_step3} queries.')

    print(f'[*] total queries: {sum([queries_step1, queries_step2, queries_step3])}')
    return mmin, mmax

def add_interval(lower, upper):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Lower bound: ', str(lower).encode())
    conn.sendlineafter(b'Upper bound: ', str(upper).encode())

def oracle(f, c, e, N):
    global QUERIES_USED
    QUERIES_USED += 1
    ct = c * pow(f, e, N) % N
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'queries: ', str(ct).encode())
    r = int(conn.recvline().decode())
    return r == -1

# context.log_level = 'debug'
# conn = process('./rsa-interval-oracle-ii.py')
conn = remote('0.0.0.0', 1337)

N = int(conn.recvline().decode())
e = 0x10001
secret_ct = int(conn.recvline().decode())

B = 2**376
add_interval(0, B)

secret_lower, secret_upper = manger(secret_ct, N, e, oracle, B)

if secret_upper - secret_lower > 2**24:
    print('Attack failed, try again...')
    exit()

for secret in range(secret_lower, secret_upper + 1):
    if pow(secret, e, N) == secret_ct:
        conn.sendlineafter(b'> ', b'3')
        conn.sendlineafter(b'Enter secret: ', str(secret).encode())
        print(conn.recvline().decode())
        break
