import itertools
from tqdm import tqdm
from multiprocessing import Pool, Manager
from functools import lru_cache
from string import ascii_uppercase, digits

# https://stackoverflow.com/questions/57354700/starmap-combined-with-tqdm/57364423#57364423
import multiprocessing.pool as mpp
def istarmap(self, func, iterable, chunksize=1):
    """starmap-version of imap
    """
    self._check_running()
    if chunksize < 1:
        raise ValueError(
            "Chunksize must be 1+, not {0:n}".format(
                chunksize))

    task_batches = mpp.Pool._get_tasks(func, iterable, chunksize)
    result = mpp.IMapIterator(self)
    self._taskqueue.put(
        (
            self._guarded_task_generation(result._job,
                                          mpp.starmapstar,
                                          task_batches),
            result._set_length
        ))
    return (item for chunk in result for item in chunk)
mpp.Pool.istarmap = istarmap

W, H, N = 6, 4, 3

class Game:
    def __init__(self, W, H, N):
        self.W = W
        self.H = H
        self.N = N

        self._LOCATIONS = sum([[(c, r) for c in range(W)] for r in range(H)], [])
        self._TARGETS = list(itertools.combinations(self._LOCATIONS, 3))
        
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

    @staticmethod
    def _score(guess, targets, scores):
        score = 0
        for t in targets:
            l = Game.get_all_consistent(t, guess, targets)
            score += len(l)
        scores[tuple(guess)] = score/len(targets)


# Precomputation 1. We want to precompute the best first guess. We do this
# by bruteforcing all possible guesses and seeing how much it
# prunes the remaining possible targets.
# This could be sped up significantly by exploiting the symmetry of the board.
def find_best_first_guess():
    game = Game(W, H, N)

    pool = Pool(8)
    manager = Manager()
    scores = manager.dict()
    for _ in tqdm(pool.istarmap(Game._score, zip(game._TARGETS, itertools.repeat(game._TARGETS), itertools.repeat(scores))), total=len(game._TARGETS)):
        pass
    pool.close()
    pool.join()

    with open('scores.txt', 'w') as f:
        s = '\n'.join([f'{str(k)} {scores[k]}' for k in sorted(scores, key=lambda k: scores[k])])
        f.write(s)


# Precomputation 2. Based on the first guess, calculate a list of the best
# second guesses in a similar way. We bucket the guess based on
# the number of remaining possible targets after receiving the
# feedback from the first guess.
def get_best_second_guess(first_guess):
    game = Game(W, H, N)

    all_n = set()
    best_second_guesses = {}
    for target in game._TARGETS:
        feedback = Game.feedback(target, first_guess)
        pruned = [t for t in game._TARGETS if Game.is_consistent(t, first_guess, feedback)]
        if len(pruned) in all_n:
            continue
        all_n.add(len(pruned))

        next_guess = min(pruned, key=lambda g: Game.score(g, targets=pruned))
        best_second_guesses[len(pruned)] = next_guess

        print(len(pruned), next_guess, Game.score(next_guess, targets=pruned))
    return best_second_guesses


find_best_first_guess()
# best_first_guess = ((0, 0), (5, 0), (0, 1))

best_second_guesses = get_best_second_guess(best_first_guess)
# best_second_guesses = {1: ((0, 0), (5, 0), (0, 1)),
#                        5: ((0, 0), (0, 1), (3, 2)),
#                        13: ((0, 0), (0, 1), (3, 3)),
#                        36: ((5, 0), (0, 3), (5, 3)),
#                        45: ((0, 0), (5, 0), (4, 3)),
#                        55: ((5, 0), (3, 3), (5, 3)),
#                        74: ((3, 0), (5, 2), (5, 3)),
#                        105: ((1, 0), (4, 0), (1, 3)),
#                        109: ((4, 0), (3, 3), (5, 3)),
#                        121: ((1, 0), (0, 3), (5, 3)),
#                        135: ((2, 0), (5, 2), (5, 3)),
#                        153: ((4, 0), (0, 1), (1, 3)),
#                        154: ((5, 2), (0, 3), (5, 3)),
#                        156: ((0, 0), (2, 3), (4, 3)),
#                        171: ((4, 0), (2, 3), (4, 3)),
#                        185: ((0, 0), (5, 2), (3, 3)),
#                        228: ((1, 0), (3, 2), (5, 3)),
#                        232: ((0, 2), (5, 2), (0, 3))}
