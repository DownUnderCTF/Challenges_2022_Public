from pwn import *
from kyber_util import *
import time
import ctypes
import hashlib

q = 3329
F = GF(q)
P.<X> = PolynomialRing(F)
R.<Xbar> = P.quotient_ring(X^256 + 1)

ORACLE_QUERIES = 0
def oracle(z, ct):
    global ORACLE_QUERIES
    ORACLE_QUERIES += 1
    conn.sendlineafter(b'> ', b'dec ' + ct.hex().encode())
    ss = conn.recvline().decode().strip().split('ss: ')[1]
    expected_ss_if_different = kdf(z + hash_h(ct)).hex()
    return ss == expected_ss_if_different

def recover_error_coefficient(z, ct, hm, idx):
    lower = 0
    upper = 1200
    v = bytes_to_poly(ct[-384:])
    while lower <= upper:
        middle = (upper + lower) // 2
        v_ = v + middle * Xbar^idx
        v_ = poly_to_bytes(v_)
        r = oracle(z, ct[:-384] + v_)
        if r:
            v_ = v + (middle - 1) * Xbar^idx
            v_ = poly_to_bytes(v_)
            r = oracle(z, ct[:-384] + v_)
            if not r:
                b = (hm[idx // 8] >> (idx % 8)) & 1
                return 833 - b - middle
            else:
                upper = middle - 1
        else:
            lower = middle + 1

def recover_error_polynomial(z, ct, hm):
    coeffs = []
    for i in range(256):
        c = recover_error_coefficient(z, ct, hm, i)
        coeffs.append(c)
    return R(coeffs)

conn = remote('0.0.0.0', 1337)
pk = bytes.fromhex(conn.recvline().decode().strip().split('pk: ')[1])
hpk = bytes.fromhex(conn.recvline().decode().strip().split('H(pk): ')[1])
z = hpk[-32:]

ct1, _, hm1 = kem_enc(pk)
ct2, _, hm2 = kem_enc(pk)

timer_start = time.time()
E1 = recover_error_polynomial(z, ct1, hm1)
print(f'[!] used {ORACLE_QUERIES} in {time.time() - timer_start:.2f}s to recover E1: {list(E1)}')
timer_start = time.time()
E2 = recover_error_polynomial(z, ct2, hm2)
print(f'[!] used total {ORACLE_QUERIES} in {time.time() - timer_start:.2f}s to recover E2: {list(E2)}')

u1 = compressed_bytes_to_polyvec(ct1[:640])
v1 = bytes_to_poly(ct1[-384:])
m1 = poly_frommsg(hm1)
y1 = v1 - E1 - m1

u2 = compressed_bytes_to_polyvec(ct2[:640])
v2 = bytes_to_poly(ct2[-384:])
m2 = poly_frommsg(hm2)
y2 = v2 - E2 - m2

s1 = (y2 - y1 * u1[0]^-1 * u2[0]) * (u2[1] - u1[0]^-1 * u1[1] * u2[0])^-1
s0 = (y1 - s1 * u1[1]) * u1[0]^-1
s = vector(R, [s0, s1])
print(f'[+] recovered secret key:', list(s[0]), list(s[1]))
s = (ctypes.c_int16 * int(2 * 256))(*(list(s[0]) + list(s[1])))
kyber_lib.pqcrystals_kyber512_ref_polyvec_ntt(s)
s = vector(R, [R(s[:256]), R(s[256:])])
s_bytes = polyvec_to_bytes(s)

conn.sendlineafter(b'> ', b'hax')
flag_enc = bytes.fromhex(conn.recvline().decode().strip().split('flag_enc: ')[1])
flag = xor(flag_enc, s_bytes[:len(flag_enc)])
print(flag.decode())
