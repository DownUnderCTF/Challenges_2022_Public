#!/usr/bin/env sage
R.<x> = PolynomialRing(GF(2))
F.<alpha> = GF(2^4, modulus=x^4+x+1)
P = PolynomialRing(F, [f'k{i}' for i in range(8)])
K = P.gens()

SBOX = [8, 11, 14, 13, 4, 7, 2, 1, 3, 0, 5, 6, 15, 12, 9, 10]
PBOX = [0, 5, 7, 6, 3, 2, 1, 4]
RC = [0x91bb3fc1, 0x139b37ca, 0x9bccd3de, 0x37d8eae1, 0x19f8ba7c, 0x338a8b1c, 0xbad8143e, 0xd8e8bab1]

def sbox(z):
    return z*(alpha+1) + alpha^3

def encrypt(pt, key1):
    keys = []
    for j in range(8):
        for rc in RC:
            r = (j * rc * pt) & 0xffffffff
            r_nibbles = [int(t, 16) for t in f'{r:08x}']
            keys.append([k + F.fetch_int(p) for k, p in zip(key1, r_nibbles)])

    pt_nibbles = [int(t, 16) for t in f'{pt:08x}']
    ct = [k + F.fetch_int(p) for k, p in zip(keys[0], pt_nibbles)]
    for j in range(1, 64):
        ct = [sbox(z) for z in ct]
        ct_ = ['?' for _ in range(8)]
        for i, p in enumerate(PBOX[::-1]):
            ct_[7-p] = ct[i]
        ct = ct_
        ct = [k + p for k, p in zip(keys[j], ct)]

    return ct

def recover_key(pt, ct):
    cts = encrypt(pt, K)
    ct = [F.fetch_int(int(t, 16)) for t in f'{ct:08x}']
    h = [c - c_ for c, c_ in zip(cts, ct)]
    V = Ideal(h).variety()[0]
    key = int(''.join([hex(V[k].integer_representation())[2:] for k in K]), 16)
    return key

enc_ptr = int(input('input an encrypted ptr: '), 16)
key = recover_key(enc_ptr & 0xffffffff, enc_ptr >> 32)
print('[+] recovered key:', hex(key))
to_enc = int(input('input a pointer to encrypt: '), 16)
enc = encrypt(to_enc & 0xffffffff, [F.fetch_int(int(t, 16)) for t in f'{key:08x}'])
enc = int(''.join([hex(t.integer_representation())[2:] for t in enc]), 16)
print('[+] encrypted ptr:', hex((enc << 32) | (to_enc & 0xffffffff)))
