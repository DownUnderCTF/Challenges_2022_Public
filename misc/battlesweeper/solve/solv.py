from pwn import process, remote
import random, itertools
from tqdm import tqdm
from functools import lru_cache
from string import ascii_uppercase, digits

W, H, N = 6, 4, 3

class Game:
    def __init__(self, W, H, N):
        self.W = W
        self.H = H
        self.N = N

        self._LOCATIONS = sum([[(c, r) for c in range(W)] for r in range(H)], [])
        self._TARGETS = list(itertools.combinations(self._LOCATIONS, 3))
        
    def parse_location(self, s):
        assert len(s) == 2
        assert s[0] in ascii_uppercase[:self.W]
        assert s[1] in digits[:self.H]
        c = ascii_uppercase[:self.W].index(s[0])
        r = digits[:self.H].index(s[1])
        return (c, r)

    @staticmethod
    def location_to_str(l):
        return ascii_uppercase[l[0]] + digits[l[1]]

    @staticmethod
    def distance(l1, l2):
        c1, r1 = l1
        c2, r2 = l2
        return max(abs(c1 - c2), abs(r1 - r2))

    @staticmethod
    def hits(target, guesses, dist):
        return set([g for g in guesses if any([Game.distance(l, g) == dist for l in target])])

    @staticmethod
    @lru_cache(2**20)
    def feedback(target, guesses):
        zeros = Game.hits(target, guesses, 0)
        ones = Game.hits(target, set(guesses) - zeros, 1)
        twos = Game.hits(target, set(guesses) - zeros - ones, 2)
        return (len(zeros), len(ones), len(twos))

    @staticmethod
    def is_consistent(target, guess, guess_feedback):
        return guess_feedback == Game.feedback(target, guess)

    @staticmethod
    def get_all_consistent(target, guess, targets):
        guess_feedback = Game.feedback(target, guess)
        return [t for t in targets if Game.is_consistent(t, guess, guess_feedback)]

    @staticmethod
    def score(guess, targets):
        score = 0
        for t in targets:
            l = Game.get_all_consistent(t, guess, targets)
            score += len(l)
        return score/len(targets)


best_first_guess = ((0, 0), (5, 0), (0, 1))

best_second_guesses = {1: ((0, 0), (5, 0), (0, 1)),
                       5: ((0, 0), (0, 1), (3, 2)),
                       13: ((0, 0), (0, 1), (3, 3)),
                       36: ((5, 0), (0, 3), (5, 3)),
                       45: ((0, 0), (5, 0), (4, 3)),
                       55: ((5, 0), (3, 3), (5, 3)),
                       74: ((3, 0), (5, 2), (5, 3)),
                       105: ((1, 0), (4, 0), (1, 3)),
                       109: ((4, 0), (3, 3), (5, 3)),
                       121: ((1, 0), (0, 3), (5, 3)),
                       135: ((2, 0), (5, 2), (5, 3)),
                       153: ((4, 0), (0, 1), (1, 3)),
                       154: ((5, 2), (0, 3), (5, 3)),
                       156: ((0, 0), (2, 3), (4, 3)),
                       171: ((4, 0), (2, 3), (4, 3)),
                       185: ((0, 0), (5, 2), (3, 3)),
                       228: ((1, 0), (3, 2), (5, 3)),
                       232: ((0, 2), (5, 2), (0, 3))}


# For the guesses after the second guess, we can just
# compute the best next step on the go.
def next_guess(prev_guesses, prev_feedback, remaining):
    pruned = [t for t in remaining if Game.is_consistent(t, prev_guesses, prev_feedback)]
    guess = min(pruned, key=lambda g: Game.score(g, targets=pruned))
    return guess, pruned


def format_guess(g):
    return ' '.join([Game.location_to_str(g_) for g_ in g]).encode()


def send_guess(g):
    conn.sendlineafter(b'Enter guess: ', format_guess(g))
    res = conn.recvline().decode().strip().split(' ')
    return tuple(map(int, res))


def play_round():
    game = Game(W, H, N)

    conn.recvline()
    feedback = send_guess(best_first_guess)
    if feedback == (3, 0, 0):
        return True

    pruned = [t for t in game._TARGETS if Game.is_consistent(t, best_first_guess, feedback)]
    best_guess = best_second_guesses[len(pruned)]
    feedback = send_guess(best_guess)
    if feedback == (3, 0, 0):
        return True

    while True:
        best_guess, pruned = next_guess(best_guess, feedback, pruned)
        feedback = send_guess(best_guess)
        if feedback == (3, 0, 0):
            return True


while True:
    # conn = process('./battlesweeper.py', level='error')
    conn = remote('0.0.0.0', 1337)
    for _ in tqdm(range(60)):
        play_round()
    res = conn.recvline().decode().strip()
    print(res)
    flag = conn.recvline().decode().strip()
    if 'DUCTF' in flag:
        print(flag)
        break
    conn.close()
