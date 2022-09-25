from pwn import *
from math import ceil
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

KNOWN_PT = b'Decrypt this... '
IV = b'A' * 16

def encrypt(iv):
    conn.sendlineafter(b'iv: ', iv.hex().encode())
    return bytes.fromhex(conn.recvline().decode().strip())

# conn = process('./chall.py')
conn = remote('0.0.0.0', 1337)

ct1 = encrypt(IV)
E_IV = strxor(KNOWN_PT, ct1[:16])

ct2 = encrypt(E_IV)
Ei_IV = strxor(KNOWN_PT, ct2[:16])

pt = b''
for i in range(1, ceil(len(ct1)/16)):
    C_i = ct1[i * 16 : (i + 1) * 16]
    P_i = strxor(Ei_IV[:len(C_i)], C_i)
    Ei_IV = strxor(P_i, ct2[i * 16 : (i + 1) * 16])
    pt += P_i

flag = pt.decode().split(' ')[1]
print(flag)
