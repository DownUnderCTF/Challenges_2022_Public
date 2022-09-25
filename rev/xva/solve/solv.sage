"""
Refer to avx2 docs (e.g. https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#techs=AVX2).
A lot of junk at the start of the check function is just loading data into registers.
Data is stored as vectors and can hold up to 256 bits. There is a (small amount of) mixed
usage of 16 bit elements and 32 bit elements in the program.
Key instructions are vpaddw, vpermd, vpmullw, vpsubw.

Input is loaded as 16 bit integers and modified as follows:

1. add 0x419b to each 16 bit element
3. let p1 = permute 32 bit elements according to the permutation (1, 3, 4, 7, 6, 0, 1, 3)
3. let p2 = permute 32 bit elements according to the permutation (5, 4, 7, 6, 2, 3, 0, 1)
4. multiply 16 bit elements by p2 (and keep the low 16 bits)
5. subtract 16 bit elements by p1

The result is stored as 32 bit unsigned integers and compared with hardcoded values.

The operations result in a multivariate quadratic system of equations which can be solved
with z3 or Grobner bases.
"""

PERM1 = [1, 3, 4, 7, 6, 0, 1, 3]
PERM2 = [5, 4, 7, 6, 2, 3, 0, 1]
ANS = [0x85765e6f, 0x7b761fa8, 0x05306ec9, 0xbd5d8cfa, 0xc2db0af6, 0x6cf52153, 0xabec2bcd, 0x5c211278]
ANS_SHORTS = []
for ans in ANS:
    ANS_SHORTS.append(ans >> 16)
    ANS_SHORTS.append(ans & 0xffff)

P = PolynomialRing(Zmod(2^16), [f's{i}' for i in range(16)])
Svars = list(P.gens())
S = Svars
S = []
for S_ in [Svars[::-1][i:i+2] for i in range(0, len(Svars), 2)]:
    S.append(S_[1])
    S.append(S_[0])

res = [(s + 0x419b) for s in S]
permed_shorts_1 = []
for p in PERM1[::-1]:
    permed_shorts_1.append(res[2*p])
    permed_shorts_1.append(res[2*p+1])
permed_shorts_2 = []
for p in PERM2[::-1]:
    permed_shorts_2.append(res[2*p])
    permed_shorts_2.append(res[2*p+1])
shorts = []
for w, p1, p2 in zip(res, permed_shorts_1, permed_shorts_2):
    shorts.append((w * p2) - p1)

eqs = [s - a for s, a in zip(shorts, ANS_SHORTS)]
eqs.append(Svars[0] - int.from_bytes('UD'.encode(), 'big'))
eqs.append(Svars[1] - int.from_bytes('TC'.encode(), 'big'))
eqs.append(Svars[2] - int.from_bytes('{F'.encode(), 'big'))
G = Ideal(eqs).groebner_basis()
b = bytearray()
for g in G:
    r = g.univariate_polynomial().change_ring(ZZ).roots()[0][0]
    b += int(r & 0xffff).to_bytes(2, 'little')
b[11] -= 0x80
b[21] -= 0x80
print(b.decode())

# DUCTF{A_V3ry_eXc3ll3n7_r3v3rs3r}
