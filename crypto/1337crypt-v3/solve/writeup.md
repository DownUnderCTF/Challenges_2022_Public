# 1337crypt v3

We are given some real numbers $\alpha_1, \alpha_2, \alpha_3, \beta_1, \beta_2, \beta_3$ to $D = 1337$ bits of precision, and a ciphertext $c$. The ciphertext is computed by XORing the (padded) flag by a random $780$-bit integer $x$. The real numbers we are provided give us hints we must use to recover $x$. The following equations summarise the challenge:

$$
\begin{aligned}
    \begin{cases}
        \sin(\alpha_1 x) &= \beta_1 \\
        \cos(\alpha_2 x) &= \beta_2 \\
        \tan(\alpha_3 x) &= \beta_3 \\
        c &= x \oplus \mathrm{pad}(\mathrm{flag}) \\
    \end{cases}
\end{aligned}
$$

The padding applied to the flag simply adds random bits to the end of the flag as an integer so that it has the same bit length as $x$. An important observation we can immediately make is that $c$ reveals some bits of $x$ because we know the upper bits of the flag from the flag format. We get the top 47 bits of $x$ from this, which we'll use later.

The goal is clearly to recover $x$, so it makes sense to see if we can manipulate the equations we have to get some useful relations in terms of $x$. The trigonometric functions, though not invertible on $\mathbb{R}$, have inverses on restricted domains. We might be tempted to apply the inverse functions to the $\beta_i$ to get something like

$$
\begin{aligned}
    \begin{cases}
        \alpha_1 x &= \arcsin(\beta_1)\\
        \alpha_2 x &= \arccos(\beta_2) \\
        \alpha_3 x &= \arctan(\beta_3) \\
    \end{cases}
\end{aligned}
$$

but a quick double checking shows that these equations don't actually hold; $\arcsin(\beta_1)$ is in the range $(-\frac{\pi}{2}, \frac{\pi}{2})$ and $\alpha_1 x$ is larger than $2^{780}$.

However, recalling that the trigonometric functions are periodic, we can develop a new set of equations which are slightly more accurate:

$$
\begin{aligned}
    \begin{cases}
        \alpha_1 x &= \arcsin(\beta_1) \pmod{2\pi} \\
        \alpha_2 x &= \arccos(\beta_2) \pmod{2\pi} \\
        \alpha_3 x &= \arctan(\beta_3) \pmod{\pi} \\
    \end{cases}
\end{aligned}
$$

The only thing missing is to account for phase shifts; the first equation could potentially be

$$
\alpha_1 x = \pm \pi - \arcsin(\beta_1) \pmod{2\pi}
$$

and the second equation could potentially be

$$
\alpha_2 x = -\arccos(\beta_2) \pmod{2\pi}
$$

Since there are just a few possibilities here, we can easily enumerate them and  otherwise ignore this detail. For simplicity, from now on we will just write $r_1, r_2, r_3$:

$$
\begin{aligned}
    r_1 &\in \{ \arcsin(\beta_1), \pm \pi - \arcsin(\beta_1) \} \\
    r_2 &\in \{ \pm \arccos(\beta_2) \} \\
    r_3 &= \arctan(\beta_3)
\end{aligned}
$$

Now, we have three linear equations in $x$, except they're slightly annoying to work with as they are equations over the reals. Fortunately, we have good precision on the numbers, so we can lift them to integers by multiplying by an appropriate scaling factor and rounding. Experimentations showed that a good choice of scaling factor is $2^D$. We will denote the scaled integer of a real value $y$ by $S(y)$.

The first equation can be scaled and written as

$$
S(\alpha_1) \cdot x = S(r_1) \pmod{S(2\pi)}
$$

Note that because of (lack of) precision, this equation isn't actually true; there is a small error that we need to account for. More accurately, we could write

$$
S(\alpha_1) \cdot x = S(r_1) + k_1 \pmod{S(2\pi)}
$$

where $k_1$ is a "small" integer. By small, we mean small relative to the size of the modulus, which should be around the same size as the scaling factor. We can do the same for the other two equations to get

$$
\begin{aligned}
    \begin{cases}
        S(\alpha_1) \cdot x &= S(r_1) + k_1 \pmod{S(2\pi)} \\
        S(\alpha_2) \cdot x &= S(r_2) + k_2 \pmod{S(2\pi)} \\
        S(\alpha_3) \cdot x &= S(r_3) + k_3 \pmod{S(\pi)} \\
    \end{cases}
\end{aligned}
$$

We know some bits of $x$, so we can write $x = \bar{x} + x'$ where $\bar{x}$ is the known bits and $x'$ is the unknown part. Replacing $x$ in the equations above and rearranging, we have

$$
\begin{aligned}
    \begin{cases}
        S(\alpha_1) \cdot x' + (S(\alpha_1) \cdot \bar{x} - S(r_1)) &= k_1 \pmod{S(2\pi)} \\
        S(\alpha_2) \cdot x' + (S(\alpha_2) \cdot \bar{x} - S(r_2)) &= k_2 \pmod{S(2\pi)} \\
        S(\alpha_3) \cdot x' + (S(\alpha_3) \cdot \bar{x} - S(r_3)) &= k_3 \pmod{S(\pi)} \\
    \end{cases}
\end{aligned}
$$

or

$$
\begin{aligned}
    \begin{cases}
        S(\alpha_1) \cdot x' + (S(\alpha_1) \cdot \bar{x} - S(r_1)) + \ell_1 S(2\pi) &= k_1 \\
        S(\alpha_2) \cdot x' + (S(\alpha_2) \cdot \bar{x} - S(r_2)) + \ell_2 S(2\pi) &= k_2 \\
        S(\alpha_3) \cdot x' + (S(\alpha_3) \cdot \bar{x} - S(r_3)) + \ell_3 S(\pi) &= k_3 \\
    \end{cases}
\end{aligned}
$$

which is a hidden number problem instance. It can be calculated, or found experimentally that the $|k_i|$ are bounded above by $B = 2^{800}$. So, we consider the lattice with basis given by the rows of the following matrix:

$$
\begin{bmatrix}
    S(2\pi) & & & & \\
    & S(2\pi) & & & \\
    & & S(\pi) & & \\
    S(\alpha_1) & S(\alpha_2) & S(\alpha_3) & B/2^{780 - 47} & \\
    S(\alpha_1) \bar{x} - S(r_1) & S(\alpha_2) \bar{x} - S(r_2) & S(\alpha_3) \bar{x} - S(r_3) & 0 & B

\end{bmatrix}
$$

The linear combination

$$
\mathbf{t} = (\ell_1, \ell_2, \ell_3, x', 1)
$$

generates the _short_ lattice vector

$$
\mathbf{v} = (k_1, k_2, k_3, Bx'/2^{780 - 47}, B)
$$

and so lattice reduction may reveal it. From this, we can read off the value of $x'$ and recover $x = \bar{x} + x'$.

Once we have $x$, we simply compute $m = c \oplus x$ and remove the padding from $m$ by right shifting iteratively until the flag is revealed.
