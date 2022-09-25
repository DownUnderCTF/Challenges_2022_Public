from pwn import *
from collections import Counter
import itertools
import os
import random


def rol(x, d):
    return ((x << d) | (x >> (32 - d))) & 0xffffffff

def bytes_to_words(B):
    return [int.from_bytes(B[i:i+4], 'little') for i in range(0, len(B), 4)]

def words_to_bytes(W):
    return b''.join([w.to_bytes(4, 'little') for w in W])


class faulty_arx:
    def __init__(self, key, nonce):
        self.ROUNDS = 20
        self.counter = 0
        self.f = 0
        self.key = key
        self.nonce = nonce

    def _init_state(self, key, nonce, counter):
        state = bytes_to_words(b'downunderctf2022')
        state += bytes_to_words(key)
        state += [counter] + bytes_to_words(nonce)
        return state

    def _QR(self, S, a, b, c, d):
        S[a] = (S[a] + S[b]) & 0xffffffff; S[d] ^= S[a]; S[d] = rol(S[d], 16)
        S[c] = (S[c] + S[d]) & 0xffffffff; S[b] ^= S[c]; S[b] = rol(S[b], 12 ^ self.f)
        S[a] = (S[a] + S[b]) & 0xffffffff; S[d] ^= S[a]; S[d] = rol(S[d], 8)
        S[c] = (S[c] + S[d]) & 0xffffffff; S[b] ^= S[c]; S[b] = rol(S[b], 7)

    def block(self):
        initial_state = self._init_state(self.key, self.nonce, self.counter)
        state = initial_state.copy()
        for r in range(0, self.ROUNDS, 2):
            self._QR(state, 0, 4, 8, 12)
            self._QR(state, 1, 5, 9, 13)
            self._QR(state, 2, 6, 10, 14)
            self._QR(state, 3, 7, 11, 15)

            x = 0
            if r == self.ROUNDS - 2:
                x = random.randint(0, 4)

            if x == 1:
                self.f = 1
            self._QR(state, 0, 5, 10, 15)
            self.f = 0

            if x == 2:
                self.f = 1
            self._QR(state, 1, 6, 11, 12)
            self.f = 0

            if x == 3:
                self.f = 1
            self._QR(state, 2, 7, 8, 13)
            self.f = 0

            if x == 4:
                self.f = 1
            self._QR(state, 3, 4, 9, 14)
            self.f = 0

        out = [(i + s) & 0xffffffff for i, s in zip(initial_state, state)]
        self.counter += 1
        return words_to_bytes(out)

    def stream(self, length):
        out = bytearray()
        while length > 0:
            block = self.block()
            t = min(length, len(block))
            out += block[:t]
            length -= t
        return out


def get_ct_with_faults_at(orig, cts, fault_pos):
    for ct in cts:
        if all(ct[f] != orig[f] for f in fault_pos):
            return ct

def get_key_candidates_from_faulted_diagonal(correct_ct, faulted_ct, fault_pos):
    o0, o1, o2, o3 = correct_ct[fault_pos[0]], correct_ct[fault_pos[1]], correct_ct[fault_pos[2]], correct_ct[fault_pos[3]]
    o0_, o1_, o2_, o3_ = faulted_ct[fault_pos[0]], faulted_ct[fault_pos[1]], faulted_ct[fault_pos[2]], faulted_ct[fault_pos[3]]

    y0 = (o0 - int.from_bytes(b'down', 'little')) % 2**32
    y0_ = (o0_ - int.from_bytes(b'down', 'little')) % 2**32

    candidates = []

    possible_b1_ = [
        2 * (y0_ - y0),
        2 * (y0_ - y0) - 1,
        2 * (y0_ - y0) + 2^32 - 1,
    ]
    procs = []
    for b1_ in possible_b1_:
        procs.append(process(['./exhaust'] + list(map(str, [b1_, o1, o1_, o2, o2_])), level='error'))
    for p in procs:
        try:
            while True:
                r = p.recvline()
                kc1, kc2 = map(int, r.decode().split())
                candidates.append((kc1, kc2))
        except EOFError:
            continue

    print([(x1.to_bytes(4, 'little').decode(), x2.to_bytes(4, 'little').decode()) for x1, x2 in candidates])
    return candidates

conn = process('../src/faulty_arx.py')
# conn = remote('0.0.0.0', 1337)
nonce = bytes.fromhex(conn.recvline().decode())
out = set([conn.recvline().decode().strip() for _ in range(5)])
cts = [bytes_to_words(bytes.fromhex(ct)) for ct in out]

# the original (unfaulted) ciphertext is the one whose words each appear the most in the other ciphertexts
correct_ct = [Counter(z).most_common()[0][0] for z in zip(*cts)]

# C1, C2, C3, C4 are the four faulted ciphertexts corresponding to the diagonals containing (k1, k6), (k2, k7), (k3, k4), (k0, k5) respectively
# we can identify which is which by checking which words differ to the correct ct
C1 = get_ct_with_faults_at(correct_ct, cts, [0, 5, 10, 15])
C2 = get_ct_with_faults_at(correct_ct, cts, [1, 6, 11, 12])
C3 = get_ct_with_faults_at(correct_ct, cts, [2, 7, 8, 13])
C4 = get_ct_with_faults_at(correct_ct, cts, [3, 4, 9, 14])

k1_k6_cands = get_key_candidates_from_faulted_diagonal(correct_ct, C1, [0, 5, 10, 15])
k2_k7_cands = get_key_candidates_from_faulted_diagonal(correct_ct, C2, [1, 6, 11, 12])
k3_k4_cands = get_key_candidates_from_faulted_diagonal(correct_ct, C3, [2, 7, 8, 13])
k0_k5_cands = get_key_candidates_from_faulted_diagonal(correct_ct, C4, [3, 4, 9, 14])

# test all candidates together to find the full key
for all_cands in itertools.product(k1_k6_cands, k2_k7_cands, k3_k4_cands, k0_k5_cands):
    k1, k6 = all_cands[0]
    k2, k7 = all_cands[1]
    k3, k4 = all_cands[2]
    k0, k5 = all_cands[3]
    key = [k0, k1, k2, k3, k4, k5, k6, k7]
    key = words_to_bytes(key)
    cipher = faulty_arx(key, nonce)
    if cipher.stream(64).hex() in out:
        print('[+] key found!', key.decode())
        break

conn.sendlineafter(b'key> ', key)
print(conn.recvline().decode())
