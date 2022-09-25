from sage.all import *
import ctypes
import hashlib

kyber_lib = ctypes.CDLL('./libpqcrystals_kyber512_ref_patched.so')
q = 3329
F = GF(q)
P = PolynomialRing(F, 'X')
P.inject_variables()
R = P.quotient_ring(X**256 + 1, 'Xbar')

def hash_h(m):
    return hashlib.sha3_256(m).digest()

def kdf(m):
    return hashlib.shake_256(m).digest(32)

def poly_to_bytes(p):
    buf = ctypes.c_buffer(int(384))
    poly = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_poly_tobytes(buf, poly)
    return bytes(buf)

def bytes_to_poly(b):
    poly = (ctypes.c_int16 * int(256))()
    kyber_lib.pqcrystals_kyber512_ref_poly_frombytes(poly, ctypes.c_buffer(b))
    return R(list(poly))

def polyvec_to_bytes(pv):
    buf = ctypes.c_buffer(int(2 * 384))
    polyvec = (ctypes.c_int16 * int(2 * 256))(*(list(pv[0]) + list(pv[1])))
    kyber_lib.pqcrystals_kyber512_ref_polyvec_tobytes(buf, polyvec)
    return bytes(buf)

def compressed_bytes_to_polyvec(b):
    polyvec = (ctypes.c_int16 * int(2 * 256))()
    kyber_lib.pqcrystals_kyber512_ref_polyvec_decompress(polyvec, ctypes.c_buffer(b))
    return vector(R, [R(list(polyvec)[:256]), R(list(polyvec)[256:])])

def poly_frommsg(m):
    poly = (ctypes.c_int16 * int(256))()
    kyber_lib.pqcrystals_kyber512_ref_poly_frommsg(poly, ctypes.c_buffer(m))
    return R(list(poly))

def kem_enc(pk):
    ct_buf = ctypes.c_buffer(int(1024))
    ss_buf = ctypes.c_buffer(int(32))
    hm_buf = ctypes.c_buffer(int(32))
    kyber_lib.pqcrystals_kyber512_ref_enc(ct_buf, ss_buf, ctypes.c_buffer(pk), hm_buf)
    return bytes(ct_buf), bytes(ss_buf), bytes(hm_buf)
