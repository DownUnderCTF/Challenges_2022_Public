from pwn import *
from collections import Counter

# https://github.com/josephsurin/lattice-based-cryptanalysis
from lbc_toolkit import ehnp


def add_interval(lower, upper):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Lower bound: ', str(lower).encode())
    conn.sendlineafter(b'Upper bound: ', str(upper).encode())

N_BITS = 384
MAX_INTERVALS = 4
MAX_QUERIES = 4700
e = 0x10001


def go():
    def query_oracle(cts):
        conn.sendlineafter(b'> ', b'2')
        conn.sendlineafter(b'queries: ', ','.join(map(str, cts)).encode())
        r = list(map(int, conn.recvline().decode().split(',')))
        return r

    conn = remote('2022.ductf.dev', 30030)

    N = int(conn.recvline().decode())
    secret_ct = int(conn.recvline().decode())

    rs = [randint(1, N) for _ in range(MAX_QUERIES)]
    cts = [pow(r, e, N) * secret_ct for r in rs]
    query_res = query_oracle(cts)
    print(Counter(query_res))

    rs_and_Us = [(r, N_BITS - (MAX_INTERVALS - i + 7)) for r, i in zip(rs, query_res) if i != -1]

    ell = len(rs_and_Us)
    print('ell:', ell)
    if ell < 55:
        conn.close()
        return False

    xbar = 0
    Pi = [0]
    Nu = [336]
    Alpha = [r for r, _ in rs_and_Us]
    Rho = [[1]] * ell
    Mu = [[U] for _, U in rs_and_Us]
    Beta = [0] * ell
    sol = ehnp(xbar, N, Pi, Nu, Alpha, Rho, Mu, Beta, delta=1/10^22, verbose=True)

    secret = -sol % N
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Enter secret: ', str(secret).encode())
    flag = conn.recvline().decode()
    print(flag)
    if 'DUCTF' in flag:
        conn.close()
        return True

while not go():
    pass
