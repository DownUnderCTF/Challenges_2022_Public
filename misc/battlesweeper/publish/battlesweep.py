#!/usr/bin/env python3

from os import path
import random
import signal
from string import ascii_uppercase, digits


FLAG = open(path.join(path.dirname(__file__), 'flag.txt'), 'r').read().strip()


class Game:
    def __init__(self, W, H, N):
        self.W = W
        self.H = H
        self.N = N

        self._LOCATIONS = sum([[(c, r) for c in range(W)] for r in range(H)], [])
        
    def parse_location(self, s):
        assert len(s) == 2
        assert s[0] in ascii_uppercase[:self.W]
        assert s[1] in digits[:self.H]
        c = ascii_uppercase[:self.W].index(s[0])
        r = digits[:self.H].index(s[1])
        return (c, r)

    def location_to_str(self, l):
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
    def feedback(target, guesses):
        zeros = Game.hits(target, guesses, 0)
        ones = Game.hits(target, set(guesses) - zeros, 1)
        twos = Game.hits(target, set(guesses) - zeros - ones, 2)
        return (len(zeros), len(ones), len(twos))

    def play_game(self):
        target = random.sample(self._LOCATIONS, self.N)
        num_guesses = 0

        while True:
            guess_inp = input('Enter guess: ')
            guesses = [self.parse_location(s) for s in guess_inp.split(' ')]
            assert len(guesses) == 3

            r = Game.feedback(target, guesses)
            print(' '.join(map(str, r)))
            num_guesses += 1

            if r == (3, 0, 0):
                break

        return num_guesses


W, H, N = 6, 4, 3
THRESHOLD_TO_WIN = 4.7
ROUNDS_TO_WIN = 60


def main():
    signal.alarm(2 * ROUNDS_TO_WIN)
    game = Game(W, H, N)
    total_guesses = 0
    for r in range(ROUNDS_TO_WIN):
        print(f'Round {r + 1}. Good luck!')
        guesses = game.play_game()
        total_guesses += guesses
    avg_guesses = total_guesses / ROUNDS_TO_WIN
    print(f'Solved {ROUNDS_TO_WIN} rounds with an average of {avg_guesses} guesses per round!')
    if avg_guesses < THRESHOLD_TO_WIN:
        print(FLAG)
    else:
        print(f'Not quite :<')


if __name__ == '__main__':
    main()
