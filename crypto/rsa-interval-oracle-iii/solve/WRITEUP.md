# rsa interval oracle

The "rsa interval oracle" series is a set of three challenges revolving around an RSA decryption oracle. The general idea is that we have an oracle which tells us whether a ciphertext decrypts to a plaintext within any of our provided intervals. The three challenges only differ in the following parameters:

- `TIMEOUT`: Server timeout (not really important here)
- `MAX_INTERVALS`: Number of intervals we can specify
- `MAX_QUERIES`: Number of queries we can send to the oracle

Summarising the functionality of the server: an `N_BIT` ($384$ in all three challenges) bit RSA modulus $N$ is generated to form an RSA public key $(N, e)$ with $e = 65537$. An `N_BIT//9` byte random secret is generated and its ciphertext $c$ is computed under the RSA public key. We are given both $N$ and $c$ and then have access to the following menu options:

1. Add interval: We specify a lower and upper bound and the interval is inserted at the start of the `intervals` list.
2. Request oracle: We specify any number of ciphertexts and the oracle checks each one, returning the index of the first interval it finds in the `intervals` list containing the ciphertext, or -1 if no interval was found. The server will then sleep for a fixed amount of time depending on the challenge parameters. The sleep time is computed as `MAX_INTERVALS * (MAX_QUERIES // N_BITS - 1)`.
3. Get flag: We send the secret value and get the flag if it is correct.

## rsa interval oracle i

In the first challenge, the parameters are

- `MAX_INTERVALS = 384`
- `MAX_QUERIES = 384`

The sleep time is `0`. This challenge is easily solved with binary search.

## rsa interval oracle ii

In the second challenge, the parameters are

- `MAX_INTERVALS = 1`
- `MAX_QUERIES = 384`

The sleep time is `0`. This challenge is solved with [Manger's attack](https://www.iacr.org/archive/crypto2001/21390229.pdf). Since the attack usually requires slightly more than $\log_2(N)$ queries, we need to take advantage of the fact that the secret plaintext is not full size; it is only $336$ bits, so we can save 40 queries by setting $f_1$ in step 1 of the attack to $2^{40}$ and solve the challenge comfortably.

## rsa interval oracle iii

In the third challenge, the parameters are

- `TIMEOUT = 180 seconds`
- `MAX_INTERVALS = 4`
- `MAX_QUERIES = 4700`

There is an "unintended" solution for rsa interval oracle ii and rsa interval oracle iii which is to choose an interval to be `(0, N//2)` and then recover a bit about the message with each query (using the same idea as a regular RSA LSB oracle attack).

The intended solution is the solution to rsa interval oracle iv which was released as a revenge challenge.

## rsa interval oracle iv

In the fourth challenge, we no longer get to choose the intervals. Instead, they are fixed by the server. Additionally, we only get one chance to query the oracle (with up to 4700 queries).

Let's cover some background first.

### The Hidden Number Problem

A (simplified) version of the hidden number problem can be stated as follows.

**(Hidden number problem).** Let $p$ be a prime and let $\alpha \in [1, p - 1]$ be a secret integer. Recover $\alpha$ given $m$ pairs of integers $\{ (t_i, a_i) \}_{i=1}^m$ such that

$$
\beta_i - t_i \alpha + a_i = 0 \pmod p
$$

where the $\beta_i$ are unknown and satisfy $|\beta_i| < B$ for some $B < p$.

For appropriate parameters, the HNP can be solved via a reduction to the closest vector problem. Consider the matrix with basis $\mathbf{B}$ given by

$$
\mathbf{B} =
\begin{bmatrix}
  p \\
  & p \\
  & & \ddots \\
  & &  & p \\
  t_1 & t_2 & \cdots & t_m & 1 / p \\
\end{bmatrix}
$$

By rewriting the HNP equations as $\beta_i + a_i = t_i \alpha + k_i p$ for integers $k_i$, we see that the linear combination $\mathbf{x} = (k_1, \ldots, k_m, \alpha)$ generates the lattice vector $\mathbf{x} \mathbf{B} = (\beta_1 + a_1, \ldots, \beta_m + a_m, \alpha / p)$. Defining $\mathbf{t} = (a_1, \ldots, a_m, 0)$ and $\mathbf{u} = (\beta_1, \ldots, \beta_m, \alpha / p)$, we notice that $\mathbf{x} \mathbf{B} - \mathbf{t} = \mathbf{u}$ where the length of $\mathbf{u}$ is bounded above by $\sqrt{m + 1} B$, whereas the lattice determinant is $p^{m-1}$. Therefore, we can reasonably expect an approximate CVP algorithm to reveal the vector $\mathbf{u}$ from which we can read off the secret integer $\alpha$ by multiplying the last entry by $p$.


### The Extended Hidden Number Problem

The [extended hidden number problem](https://link.springer.com/chapter/10.1007/978-3-540-74462-7_9) extends the HNP to the case in which there are multiple chunks of information known about linear relations of the secret integer. Additionally, it simultaneously deals with the case in which multiple chunks of the secret integer are known. It can be stated as follows.

**(Extended hidden number problem).** Let $p$ be a prime and let $x \in [1, p-1]$ be a secret integer such that

$$
x = \bar{x} + \sum_{j=1}^m 2^{\pi_j} x_j
$$

where the integers $\bar{x}$ and $\pi_j$ are known, and the unknown integers $x_j$ satisfy $0 \leq x_j < 2^{\nu_j}$ for known integers $\nu_j$. Suppose we are given $d$ equations

$$
\alpha_i \sum_{j=1}^m 2^{\pi_j} x_j + \sum_{j=1}^{l_i} \rho_{i,j} k_{i,j} = \beta_i - \alpha_i \bar{x} \pmod p
$$

for $1 \leq i \leq d$ where $\alpha_i \neq 0 \pmod p$, $\rho_{i, j}$ and $\beta_i$ are known integers. The unknown integers $k_{i,j}$ are bounded by $0 \leq k_{i,j} < 2^{\mu_{i,j}}$ where the $\mu_{i,j}$ are known. The extended hidden number problem (EHNP) is to find $x$. The EHNP instance is represented by

$$
\left ( \bar{x}, p, \{ \pi_j, \nu_j \}_{j=1}^m, \left \{ \alpha_i, \{ \rho_{i,j}, \mu_{i,j} \}_{j=1}^{l_i}, \beta_i \right \}_{i=1}^d \right )
$$

As with the hidden number problem, we model the situation as a CVP instance. The main idea behind the lattice basis used to solve the EHNP is similar to that of the regular HNP except the EHNP lattice involves factors to deal with the varying sizes of the unknown chunks. For a $\delta > 0$, we construct the EHNP lattice basis $\mathbf{B}$:

$$
\mathbf{B} =
\begin{bmatrix}
  p \cdot \mathbf{I}_{d} \\
  \mathbf{A} & \mathbf{X} \\
  \mathbf{R} & & \mathbf{K}
\end{bmatrix}
$$

with the following definitions:

$$
\begin{aligned}
  % L &= \sum_{i=1}^d l_i \\
  % D &= d + m + L \\
  \mathbf{A} &=
  \begin{bmatrix}
    \alpha_1 2^{\pi_1} & \alpha_2 2^{\pi_1} & \cdots & \alpha_d 2^{\pi_1} \\
    \alpha_1 2^{\pi_2} & \alpha_2 2^{\pi_2} & \cdots & \alpha_d 2^{\pi_2} \\
    \vdots & \ddots & & \vdots \\
    \alpha_1 2^{\pi_m} & \alpha_2 2^{\pi_m} & \cdots & \alpha_d 2^{\pi_m}
  \end{bmatrix}
  &&\qquad
  \mathbf{X} = \mathrm{diag} \left ( \frac{\delta}{2^{\nu_1}}, \frac{\delta}{2^{\nu_2}}, \ldots, \frac{\delta}{2^{\nu_m}} \right ) \\
  \mathbf{R} &=
  \begin{bmatrix}
    \rho_{1,1} \\ \vdots \\ \rho_{1,l_1} \\
    & \ddots \\
    & & \rho_{d,1} \\ & & \vdots \\ & & \rho_{d,l_d} \\
  \end{bmatrix}
   &&\qquad
   \mathbf{K} = \mathrm{diag} \left ( \frac{\delta}{2^{\mu_{1,1}}}, \ldots, \frac{\delta}{2^{\mu_{1,l_1}}}, \ldots, \frac{\delta}{2^{\mu_{d,1}}}, \ldots, \frac{\delta}{2^{\mu_{d,l_d}}} \right )
\end{aligned}
$$

To understand what vector we should target with CVP, we rewrite the EHNP equations as

$$
\alpha_i \sum_{j=1}^m 2^{\pi_j} x_j + \sum_{j=1}^{l_i} \rho_{i,j} k_{i,j} + r_i p = \beta_i - \alpha_i \bar{x}

$$
for integers $r_i$. Now, consider the lattice vector $\mathbf{u}$ generated by the linear combination $\mathbf{x}$ which contains secret information:

$$
\mathbf{x} = (r_1, \ldots, r_d, x_1, \ldots, x_m, k_{1,1}, \ldots, k_{1,l_1}, \ldots, k_{d,1}, \ldots, k_{d,l_d})
$$

We have

$$
\mathbf{x} \mathbf{B} = \mathbf{u} = \left (\beta_1 - \alpha_1 \bar{x}, \ldots, \beta_d - \alpha_d \bar{x}, \frac{x_1 \delta}{2^{\nu_1}}, \ldots, \frac{x_m \delta}{2^{\nu_m}}, \frac{k_{1,1} \delta}{2^{\mu_{1,1}}}, \ldots, \frac{k_{1,l_1} \delta}{2^{\mu_{1,l_1}}}, \ldots, \frac{k_{d,1} \delta}{2^{\mu_{d,1}}}, \ldots, \frac{k_{d,l_d} \delta}{2^{\mu_{d,l_d}}} \right ) \\
$$

Then, letting

$$
\mathbf{w} = \left (\beta_1 - \alpha_1 \bar{x}, \ldots, \beta_d - \alpha_d \bar{x}, \frac{\delta}{2}, \ldots, \frac{\delta}{2}, \frac{\delta}{2}, \ldots, \frac{\delta}{2}, \ldots, \frac{\delta}{2}, \ldots, \frac{\delta}{2} \right )
$$

we notice that $\mathbf{w}$ is close to the lattice vector $\mathbf{u}$. Therefore, by solving the CVP instance with $\mathbf{w}$ as the target vector, we may reveal the lattice vector $\mathbf{u}$ that encodes the secret chunks $x_j$ in the $(d+1)$st to $(d+m)$th entries.


### Finding the HNP

HNP and EHNP can be applied in a large number of different situations. These are mostly characterised by having a number of identically shaped linear expressions (involving the secret value) which are bounded by some upper bound that is "small" relative to the modulus. In the challenge, we have exactly this situation.

The four intervals we have in the challenge are $(0, U_0), (0, U_1), (0, U_2), (0, U_3)$ with $U_i = 2^{384 - 8 - i}$. By sending queries of the form $r_i^e c$ for random $r_i$ and observing which interval the decryption lies in, we obtain linear relations involving the secret message $m$.

More specifically, if the oracle tells us that the decryption of $r_i^e c$ lies in the interval $(0, U_j)$, then we have

$$
\begin{aligned}
    r_i m &< U_j \pmod N \\
    \implies\beta_i - r_i m &= 0 \pmod N
\end{aligned}
$$

where $|\beta_i| < U_j$.

With many such relations, we see that what we have resembles a hidden number problem instance, though different relations will have different bounds on the $\beta_i$ term depending on which interval the decryption lies in.

### Reliability

Testing out this idea locally may show very rare or no success. The bounds are quite tight and we need to get quite lucky to get a good number of useful queries (i.e. values that actually lie within the intervals). We can increase the reliability by using the fact that the secret value itself is not full size either, which means we know some of its bits (the top 48 bits are 0). This kind of situation is handled explicitly by EHNP.

With this small optimisation, solving the challenge seems to take around 10 connections on average. We can decide whether or not we have enough information just from reading the results of the oracle, so we don't need to wait for the sleep time every connection. In most cases, we should get the flag within 5 to 30 minutes of repeatedly trying.

### Implementation

```py
from pwn import *
from collections import Counter

# https://github.com/josephsurin/lattice-based-cryptanalysis
from lbc_toolkit import ehnp


def add_interval(lower, upper):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Lower bound: ', str(lower).encode())
    conn.sendlineafter(b'Upper bound: ', str(upper).encode())

N_BITS = 384
MAX_INTERVALS = 4
MAX_QUERIES = 4700
e = 0x10001


def go():
    def query_oracle(cts):
        conn.sendlineafter(b'> ', b'2')
        conn.sendlineafter(b'queries: ', ','.join(map(str, cts)).encode())
        r = list(map(int, conn.recvline().decode().split(',')))
        return r

    conn = remote('2022.ductf.dev', 30030)

    N = int(conn.recvline().decode())
    secret_ct = int(conn.recvline().decode())

    rs = [randint(1, N) for _ in range(MAX_QUERIES)]
    cts = [pow(r, e, N) * secret_ct for r in rs]
    query_res = query_oracle(cts)
    print(Counter(query_res))

    rs_and_Us = [(r, N_BITS - (MAX_INTERVALS - i + 7)) for r, i in zip(rs, query_res) if i != -1]

    ell = len(rs_and_Us)
    print('ell:', ell)
    if ell < 55:
        conn.close()
        return False

    xbar = 0
    Pi = [0]
    Nu = [336]
    Alpha = [r for r, _ in rs_and_Us]
    Rho = [[1]] * ell
    Mu = [[U] for _, U in rs_and_Us]
    Beta = [0] * ell
    sol = ehnp(xbar, N, Pi, Nu, Alpha, Rho, Mu, Beta, delta=1/10^22, verbose=True)

    secret = -sol % N
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Enter secret: ', str(secret).encode())
    flag = conn.recvline().decode()
    print(flag)
    if 'DUCTF' in flag:
        conn.close()
        return True

while not go():
    pass
```
