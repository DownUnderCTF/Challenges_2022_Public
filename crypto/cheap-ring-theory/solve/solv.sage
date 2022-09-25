from pwn import *

p = 55899879511190230528616866117179357211
V = GF(p)^3
R.<x> = PolynomialRing(GF(p))
f = x^3 + 36174005300402816514311230770140802253*x^2 + 35632245244482815363927956306821829684*x + 10704085182912790916669912997954900147
Q = R.quotient(f)

def phi(g):
    return V([g.lift()(z) for z, _ in f.roots()])

# conn = process('./chall.sage')
conn = remote('0.0.0.0', 1337)

A = Q(list(map(int, conn.recvline().decode().strip().split())))
B = Q(list(map(int, conn.recvline().decode().strip().split())))
C = Q(list(map(int, conn.recvline().decode().strip().split())))

phi_A = phi(A)
phi_B = phi(B)
phi_C = phi(C)

conn.sendline(' '.join(map(str, phi_A)).encode())
conn.sendline(' '.join(map(str, phi_B)).encode())
conn.sendline(' '.join(map(str, phi_C)).encode())

print(conn.recvline().decode().strip())
