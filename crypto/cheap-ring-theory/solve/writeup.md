# cheap ring theory

The setting in this challenge involves a fixed prime $p$ and cubic $f(x) \in \mathbb{F}_p[x]$. Two random elements $A, B$ of $\mathbb{F}_p[x]/(f)$ are generated, along with two integers $n, m \in [1, p)$. We are given both $A$ and $B$, as well as $C$ which is computed as $C = A^n B^m$.

To get the flag, we must provide three elements $a, b, c$ of $\mathbb{F}_p^3$ which satisfy $a^n b^m = c$. If we have a homomorphism $\varphi : \mathbb{F}_p[x]/(f) \to \mathbb{F}_p^3$ then we can simply send $\varphi(A), \varphi(B), \varphi(C)$. The goal is therefore, to find a homomorphism.

Note that $f$ is cubic and factors into $f(x) = (x - \alpha_1)(x - \alpha_2)(x - \alpha_3)$; that is, it has roots $\alpha_1, \alpha_2, \alpha_3$. By the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem#Generalization_to_arbitrary_rings), we know that

$$
\frac{\mathbb{F}_p[x]}{(f)} \cong \frac{\mathbb{F}_p[x]}{(x - \alpha_1)} \oplus \frac{\mathbb{F}_p[x]}{(x - \alpha_2)} \oplus \frac{\mathbb{F}_p[x]}{(x - \alpha_3)}
$$

Then, the [First Isomorphism Theorem](https://en.wikipedia.org/wiki/Isomorphism_theorems#Theorem_A_(rings)) gives us an isomorphism between $\frac{\mathbb{F}_p[x]}{(x - \alpha_i)}$ and $\mathbb{F}_p$. Specifically, define the map

$$
\begin{aligned}
    \pi_{\alpha_i} : \mathbb{F}_p[x] &\to \mathbb{F}_p \\
                      g(x)            &\mapsto g(\alpha_i)
\end{aligned}
$$

to be the evaluation map. This map is a surjective homomorphism and importantly $\ker{\pi_{\alpha_i}}  = (x - \alpha_i)$, and so we have $\mathbb{F}_p[x]/(x - \alpha_i) \cong \mathbb{F}_p$.

Therefore, we have the map $\varphi : \mathbb{F}_p[x]/(f) \to \mathbb{F}_p^3$ defined by

$$
\begin{aligned}
    \varphi : \mathbb{F}_p[x]/(f) &\to \mathbb{F}_p^3 \\
              g(x)                &\mapsto (g(\alpha_1), g(\alpha_2), g(\alpha_3))
\end{aligned}
$$

which is a homomorphism.

Sending $\varphi(A), \varphi(B), \varphi(C)$ passes the check and prints the flag.

(unintended solution): sending `0 0 0` or `1 1 1` or nothing works too.
