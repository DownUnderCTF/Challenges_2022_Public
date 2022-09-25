* [Kyber](#kyber)
    * [Overview](#overview)
        * [$\small{\text{KYBER}}.\normalsize{\textsf{CPAPKE}}$](#smalltextkybernormalsizetextsfcpapke)
            * [$\textsf{KeyGen}()$](#textsfkeygen)
            * [$\textsf{Enc}(pk, m, r)$](#textsfencpk-m-r)
            * [$\textsf{Dec}(sk, c)$](#textsfdecsk-c)
            * [Correctness](#correctness)
        * [$\small{\text{KYBER}}.\normalsize{\textsf{CCAKEM}}$](#smalltextkybernormalsizetextsfccakem)
            * [$\textsf{KeyGen}()$](#textsfkeygen-1)
            * [$\textsf{Enc}(pk)$](#textsfencpk)
            * [$\textsf{Dec}(c, sk)$](#textsfdecc-sk)
    * [Implementation Details](#implementation-details)
        * [Serialisation](#serialisation)
        * [Compression](#compression)
        * [NTT](#ntt)
* [Challenge Overview](#challenge-overview)
    * [`my.patch`](#mypatch)
* [Solution](#solution)
    * [Bugs](#bugs)
    * [Leaking Information](#leaking-information)
        * [The Oracle](#the-oracle)
    * [Recovering $\mathbf{s}$](#recovering-mathbfs)
    * [Recovering the Error](#recovering-the-error)
    * [Recovering the Flag](#recovering-the-flag)
    * [Solve Script](#solve-script)
        * [`kyber_util.py`](#kyber_utilpy)
        * [`solv.sage`](#solvsage)

kyber± is a cryptography challenge written for DUCTF 2022. It challenge revolves around [Kyber](https://pq-crystals.org/kyber/index.shtml) and its [reference implementation](https://github.com/pq-crystals/kyber). A (crypto) bug is artificially introduced through a patch given in `my.patch`. Before we even look any further into the challenge, let's review Kyber.

# Kyber

Kyber is a lattice-based key encapsulation mechanism (KEM) which has been [selected for standardisation](https://www.nist.gov/news-events/news/2022/07/pqc-standardization-process-announcing-four-candidates-be-standardized-plus) in the NIST PQC competition. Its security is based on the LWE problem in module lattices. Although we give a brief overview in this section, the [written specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf) is an excellent resource to learn more about Kyber.

## Overview

It is important to note that Kyber itself is a KEM. It is built on top of a IND-CPA-secure public-key encryption scheme which is introduced in the specification as $\small{\text{KYBER}}.\normalsize{\textsf{CPAPKE}}$. As is common with lattice-based KEMs, the IND-CCA2-secure KEM is obtained by applying the Fujisaki-Okamoto transform (or some variant of it) to the IND-CPA-secure PKE.

At its core, all Kyber really does is just a bunch of polynomial multiplications. We work in the ring $R_q = \mathbb{Z}_q[X]/(X^n + 1)$ where $n$ and $q$ are fixed to $n = 256, q = 3329$ for all parameter sets. These parameters were chosen specifically because they lend themselves well to implementing very efficient multiplications in $R_q$. The design also makes implementation easier as the main security parameter $k$ (which is the dimension of the lattice or size of the module elements) can be adjusted without any changes in the code. For the parameter set used in the challenge ($\small{\text{KYBER}}512$), $k$ is set to $2$.

We work with three main mathematical objects: polynomials (elements of $R_q$), vectors of polynomials, and (square) matrices of polynomials. We will denote polynomials by lower-case letters, vectors by bold lower-case letters, and matrices by bold upper-case letters.

How to randomly sample these objects is also an important part of the algorithm. We will avoid the specifics and just note that "small" polynomials or vectors (such as noise) have their coefficients sampled from a centered binomial distribution with parameter of either $\eta_1$ or $\eta_2$. In $\small{\text{KYBER}}512$, we have $\eta_1 = 3$ and $\eta_2 = 2$. In all other parameter sets, $\eta_1 = \eta_2 = 2$. These parameters were selected to balance between security, ciphertext size, and decryption failure probability and are not really important for this challenge. The main takeaway is that polynomials whose coefficients are sampled from a $\mathsf{CBD}_\eta$ have (integer) coefficients in $[-\eta, \eta]$. Since coefficients can have magnitude up to $q/2$, the coefficients of polynomials sampled from these distributions can be considered "small".

We'll first give a very high level overview of the Kyber algorithms to understand the math behind it and then introduce some other important details which mostly pertain to optimistaion and implementation later.

### $\small{\text{KYBER}}.\normalsize{\textsf{CPAPKE}}$

We only give brief outlines here and refer to the [specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf) for the full details of the algorithms.

#### $\textsf{KeyGen}()$

In the Kyber PKE, the secret key $\mathbf{s} \in R_q^k$ is a vector consisting of $k$ polynomials from $R_q$ with small coefficients sampled from $\mathsf{CBD}_{\eta_1}$. The public key is $(\mathbf{t}, \mathbf{A})$ where $\mathbf{A} \in R_q^{k \times k}$ is a randomly sampled matrix and $\mathbf{t} \in R_q^k$ is computed as $\mathbf t = \mathbf{A} \mathbf{s} + \mathbf{e}$ where $\mathbf{e} \in R_q^k$ is a small error term with coefficients sampled from $\mathsf{CBD}_{\eta_1}$ (just like $\mathbf{s}$).

#### $\textsf{Enc}(pk, m, r)$

To encrypt a 32 byte message $m$, we use the public key $pk = (\mathbf{t}, \mathbf{A})$ and a randomness seed $r$. Using $r$ as a seed, a vector $\mathbf{r} \in R_q^k$ is sampled from $\mathsf{CBD}_{\eta_1}$, a noise vector $\mathbf{e}_1 \in R_q^k$ is sampled from $\mathsf{CBD}_{\eta_2}$ and a noise polynomial $e_2 \in R_q$ is sampled from $\mathsf{CBD}_{\eta_2}$. The ciphertext $(\mathbf{u}, v)$ is then computed as:

$$
\begin{aligned}
    \mathbf{u} &= \mathbf{A}^T \mathbf{r} + \mathbf{e_1} \\
    v &= \mathbf{t} \cdot \mathbf{r} + e_2 + \mu
\end{aligned}
$$

Here, $\mu$ is the polynomial obtained by using the 256 bits of the message $m$ as coefficients and multiplying by $(q+1)/2$.

#### $\textsf{Dec}(sk, c)$

Decryption is simple. Given the secret key $\mathbf{s} = sk$ and ciphertext $(\mathbf{u}, v) = c$, the message polynomial is recovered by computing

$$
\mu \approx v - \mathbf{s} \cdot \mathbf{u}
$$

To recover the actual message $m$, we look at the coefficients of $\mu$; if the coefficient is close to $0$, then the bit is a $0$, and if the coefficient is closer to $(q+1)/2$ then the bit is a $1$.

#### Correctness

By looking at the encryption and decryption equations, we can gain an intuition for the correctness of the scheme. Note that we also write $\mathbf{x} \cdot \mathbf{y} = \mathbf{x}^T \mathbf{y}$.

$$
\begin{aligned}
    v - \mathbf{s} \cdot \mathbf{u} &= \mathbf{t} \cdot \mathbf{r} + e_2 + \mu - \mathbf{s} \cdot (\mathbf{A}^T \mathbf{r} + \mathbf{e}_1) \\
                                    &= \mathbf{t} \cdot \mathbf{r} + e_2 + \mu - \mathbf{s}^T \mathbf{A}^T \mathbf{r} - \mathbf{s} \cdot \mathbf{e}_1 \\
                                    &= \mathbf{t} \cdot \mathbf{r} + e_2 + \mu - (\mathbf{A} \mathbf{s}) \cdot \mathbf{r} - \mathbf{s} \cdot \mathbf{e}_1 \\
                                    &= (\mathbf{t} - \mathbf{A} \mathbf{s}) \cdot \mathbf{r} + e_2 + \mu - \mathbf{s} \cdot \mathbf{e}_1 \\
                                    &= \mathbf{e} \cdot \mathbf{r} + e_2 + \mu - \mathbf{s} \cdot \mathbf{e}_1 \\
                                    &= \underbrace{\mathbf{e} \cdot \mathbf{r} + e_2 - \mathbf{s} \cdot \mathbf{e}_1}_{\text{small}} + \mu \\
\end{aligned}
$$

The combined error term $\mathbf{e} \cdot \mathbf{r} + e_2 - \mathbf{s} \cdot \mathbf{e}_1$ contains only "small" polynomials, so the result is quite small too. It follows that the approximation holds and $m$ can be decoded correctly with quite high probability. The specification goes into more detail and includes calculations for the decryption failure probability in each parameter set.

### $\small{\text{KYBER}}.\normalsize{\textsf{CCAKEM}}$

The KEM involves three algorithms: KeyGen, Encapsulate, Decapsulate. All of these algorithms make use of symmetric primitives. Of interest are two hash functions $H$ (256 bits) and $G$ (512 bits), and a key-derivation function $\mathsf{KDF}$. In Kyber (not the "90s" variant), these are instantiated as follows:

|Primitive|Instantiation|
|---|---|
|$H$|$\text{SHA3-256}$|
|$G$|$\text{SHA3-512}$|
|$\mathsf{KDF}$|$\text{SHAKE-256}$|

Since we will be hashing abstract math objects, there is a need to define a way to encode (and decode) such objects as bytes. For now, we'll ignore this detail and focus on the main ideas behind the KEM algorithms.

#### $\textsf{KeyGen}()$

The KEM key generation involves generating a PKE key pair $(pk, sk')$. The public key is just $pk$, and the secret key is $sk = (sk'||pk||H(pk)||z)$ where $z$ is a pseudorandom 32 byte value (which is used during decapsulation). The hash of the public key is included in the secret key to speed up decapsulation.

#### $\textsf{Enc}(pk)$

The goal of encapsulation is to generate a symmetric key material as well as a ciphertext which can be decapsulated using the secret key. A 32 byte value $m$ is randomly generated (the specification actually takes $m$ to be the hash of a 32 byte random value to avoid using the output of the system RNG), then a pre-key $\bar{K}$ and coins $r$ are computed as $(\bar{K}, r) = G(m||H(pk))$. The ciphertext $c$ is obtained by encrypting $m$ with $pk$ and randomness $r$. Finally, the shared secret $K$ is obtained by computing $K = \mathsf{KDF}(\bar{K}||H(c))$. The output is $(c, K)$.

#### $\textsf{Dec}(c, sk)$

Decapsulation allows one with the secret key to recover the shared secret from an encapsulation ciphertext. The ciphertext is decrypted using the PKE to obtain $m'$. Then, a candidate pre-key and coins are computed as $(\bar{K}', r') = G(m'||H(pk))$. The decrypted message $m'$ is then re-encrypted with randomness $r'$ to obtain $c'$. If the two ciphertexts match, the shared secret is computed as $K = \mathsf{KDF}(\bar{K}'||H(c))$. Otherwise, it is computed as $K = \mathsf{KDF}(z||H(c))$. In the latter case, the decapsulation fails and the shared secret is meaningless.

## Implementation Details

While mostly accurate and hopefully easy to understand, our previous descriptions miss a few important details. This section will outline the main implementation details relevant in the challenge.

### Serialisation

Serialisation (and deserialisation) is the process of converting objects to and from bytes so that they can be stored, hashed, transmitted, etc. In Kyber, there is really only one object which needs this: elements of $R_q$. Since each coefficient is smaller than $q = 3329$, they can each be represented with $12$ bits. Therefore, to encode a polynomial $f \in R_q$, we simply write the $12$ bits of each coefficients (starting from the constant coefficient) and convert the bit string to bytes. It takes $\frac{12 \cdot 256}{8}$ bytes to encode an element of $R_q$.

### Compression

The Kyber specification defines compression and decompression functions for $x \in \mathbb{Z}_q$ and $d < \lceil \log_2(q) \rceil$ as follows:

$$
\begin{aligned}
    \mathsf{Compress}_q(x, d) &= \lceil (2^d/q) \cdot x \rfloor \mod 2^d \\
    \mathsf{Decompress}_q(x,d) &= \lceil (q/2^d) \cdot x \rfloor
\end{aligned}
$$

These functions do as they sound, and more specifically, if

$$
x' = \mathsf{Decompress}_q(\mathsf{Compress}(x, d), d)
$$

then

$$
|x' - x \mod q| \leq \left \lceil \frac{q}{2^{d+1}} \right \rfloor
$$

Note that the compression and decompression functions are actually used with $d = 1$ to implement encoding and decoding the message polynomial.

Their main use, however, is to reduce the ciphertext size. Compression parameters $d_u$ and $d_v$ are specified for each parameter set, and for $\small{\text{KYBER}}512$, they are $d_u = 10, d_v = 4$. This means that each coefficient of the polynomials in $\mathbf{u}$ are compressed to $10$ bits, and each coefficient in $v$ is compressed to $4$ bits. So the size of the compressed $\mathbf{u}$ vector is $\frac{2 \cdot 10 \cdot 256}{8} = 640$ bytes and the size of the compressed $v$ polynomial is $\frac{4 \cdot 256}{8} = 128$ bytes.

In fact, compressing the ciphertext seems to add some security as well. In the case of LWE, a random small error is added and in this case we effectively have extra (deterministic) noise by dropping some bits. This also has a name, and it's called "Learning with Rounding" (LWR).

### NTT

One of Kyber's (and other lattice-based schemes) main attractions is its fast speeds. Aside from the use of symmetric primitives, polynomial multiplication is the most time-consuming operation in the scheme. Fortunately, it can be implemented very efficiently using the so-called _number-theoretic transform_ (NTT). Although it isn't necessary to fully understand NTT and the associated algorithms for this challenge, we need to at least be aware of its existence.

To grossly simplify, we can multiply two polynomials $f, g \in R_q$ by transforming them into elements of the _NTT domain_ where multiplication is cheaper, and then transforming them back into their normal form after the cheap multiplication. That is, we have two functions $\mathsf{NTT} : R_q \rightarrow R_q$ and $\mathsf{invNTT} : R_q \rightarrow R_q$ and we perform polynomial multiplication by computing $f \cdot g = \mathsf{invNTT}(\mathsf{NTT}(f) \circ \mathsf{NTT}(g))$ where $\circ$ denotes multiplication in the NTT domain.

If we simply reuse the library code for the challenge, we don't need to worry about implementing this. But the main idea is that $q - 1 = 2^8 \cdot 13$ and $X^{256} + 1$ factors into $128$ degree $2$ polynomials, so we can consider $f$ and $g$ each as vectors of $128$ degree $1$ polynomials (i.e. modulo each of the degree $2$ factors of $X^{256} + 1$) and multiply them componentwise. The actual algorithm itself is essentially the Cooley-Tukey FFT algorithm with minor modifications.

# Challenge Overview

With preliminaries out of the way, we are finally ready to take a look at the challenge itself. We are given a `kyber.py` file which implements the server, a `libpqcrystals_kyber512_ref.so` library which is built from the Kyber reference implementation, `my.patch` which outlines the changes made to the reference implementation for the challenge, and a `build-kyber.sh` script which automates pulling and building the `libpqcrystals_kyber512_ref.so` file for the player's convenience (this also indicates that the Kyber reference implementation is being used as well as the specific commit).

`kyber.py`

```py
#!/usr/bin/env python3
import ctypes

MAX_QUERIES = 7681
FLAG = open('flag.txt', 'rb').read().strip()


kyber_lib = ctypes.CDLL('./libpqcrystals_kyber512_ref.so')
class Kyber:
    def __init__(self):
        self.pk_buf = ctypes.c_buffer(800)
        self.sk_buf = ctypes.c_buffer(1632)
        kyber_lib.pqcrystals_kyber512_ref_keypair(self.pk_buf, self.sk_buf)

    def kem_enc(self):
        ct_buf = ctypes.c_buffer(1024)
        ss_buf = ctypes.c_buffer(32)
        kyber_lib.pqcrystals_kyber512_ref_enc(ct_buf, ss_buf, self.pk_buf)
        return bytes(ct_buf), bytes(ss_buf)

    def kem_dec(self, c):
        assert len(c) == 1024
        ct_buf = ctypes.c_buffer(c)
        ss_buf = ctypes.c_buffer(32)
        kyber_lib.pqcrystals_kyber512_ref_dec(ss_buf, ct_buf, self.sk_buf)
        return bytes(ss_buf)


def main():
    kyber = Kyber()
    print('pk:', bytes(kyber.pk_buf).hex())
    print('H(pk):', bytes(kyber.sk_buf)[-64:].hex())

    for _ in range(MAX_QUERIES):
        try:
            inp = input('> ')
            if inp.startswith('enc'):
                ct, ss = kyber.kem_enc()
                print('ct:', ct.hex())
                print('ss:', ss.hex())
            elif inp.startswith('dec '):
                ct = bytes.fromhex(inp[4:])
                ss = kyber.kem_dec(ct)
                print('ss:', ss.hex())
            else:
                break
        except:
            print('>:(')
            exit(1)

    enc = bytes([a ^ b for a, b in zip(FLAG, bytes(kyber.sk_buf))])
    print('flag_enc:', enc.hex())


if __name__ == '__main__':
    main()
```

The server code itself is quite short and seems to not do much other than interface with the C Kyber library. It generates a Kyber key pair and gives us the public key as well as the hash of the public key. We then have access to 7681 queries where we can call either the KEM's encapsulation function or the decapsulation function with any ciphertext. After the queries, we are given the flag XORed with the secret key (its bytes serialisation).

## `my.patch`

```diff
diff --git a/ref/indcpa.c b/ref/indcpa.c
index 60f4059..f822b0d 100644
--- a/ref/indcpa.c
+++ b/ref/indcpa.c
@@ -89,7 +89,7 @@ static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEY
 static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
 {
   polyvec_compress(r, b);
-  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
+  poly_tobytes(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
 }
 
 /*************************************************
@@ -105,7 +105,7 @@ static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
 static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
 {
   polyvec_decompress(b, c);
-  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
+  poly_frombytes(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
 }
 
 /*************************************************
diff --git a/ref/params.h b/ref/params.h
index 3d02a0f..b0d929c 100644
--- a/ref/params.h
+++ b/ref/params.h
@@ -58,7 +58,7 @@
 #define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
 #define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
 #define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
-#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)
+#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYBYTES)
 
 #define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
 /* 32 bytes of additional space to save H(pk) */
diff --git a/ref/verify.c b/ref/verify.c
index ed4a654..1e88e16 100644
--- a/ref/verify.c
+++ b/ref/verify.c
@@ -19,9 +19,9 @@ int verify(const uint8_t *a, const uint8_t *b, size_t len)
   uint8_t r = 0;
 
   for(i=0;i<len;i++)
-    r |= a[i] ^ b[i];
+    r = r == 0xff ? r : r + (a[i] != b[i]);
 
-  return (-(uint64_t)r) >> 63;
+  return r;
 }
 
 /*************************************************
@@ -41,7 +41,6 @@ void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
 {
   size_t i;
 
-  b = -b;
   for(i=0;i<len;i++)
     r[i] ^= b & (r[i] ^ x[i]);
 }
```

The patch consists of two main changes:

1. The ciphertext polynomial $v$ no longer uses compression. Before, it would be compressed to 4 bits and the ciphertext would have size 768 bytes, now the ciphertext size is 1024 bytes.
2. The `verify` function is slightly changed to return values other than `0` or `1`. This function is used for the equality check during decapsulation. The `cmov` function is changed to not negate the  `b` parameter. This function is also used during decapsulation. `verify` and `cmov` are both intended to be constant time as not to leak any information about the equality of the two ciphertexts.

# Solution

With basics done and an understanding of the challenge, we can finally think about solving it. We start by looking for bugs, and the patch stands out the most so let's analyse it further.

## Bugs

We saw that the patch introduces two major changes to the KEM. The first one simply removes some compression and while that does lower security a bit (since we lose the deterministic noise which acts as an error term), its main purpose was really just for making the ciphertext size smaller (at least the specification argues for Kyber's security without relying on this rounding too much). So we turn to the second change, which seems a lot more dangerous.

We want to understand what weaknesses the changes to `verify` and `cmov` introduce, so it's helpful to see how they are used for context. Their only usage is in the KEM decapsulation function (in `kem.c`):

```c
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}
```

Just as in the algorithm description, we see that `verify` is used to check the equality of the given ciphertext `ct` and the re-encrypted ciphertext `cmp`. Before the patch, if these two values were equal then `verify` would return `0`, otherwise it would return `1`. The result is put into the `fail` variable which is passed as the last argument (the `b` parameter) to the `cmov` function. Without the patch applied, we see that if this argument is `0`, then the `cmov` function essentially does nothing. Otherwise, if the argument is `1`, then because of the `b = -b` line, and the fact that `b` is an unsigned 8 bit integer, we would have `b = 0xff` and the `kr` buffer would be overwritten by the $z$ value from the secret key.

The patch changes this behaviour in that it essentially makes `verify` return the number of byte inequalities there are between `ct` and `cmp`, with a max value of `0xff`. The change in `cmov` makes it so that the overwriting just uses the value of `fail` directly as the `&` operand. At a higher level, we see that if the two ciphertexts are exactly equal, then `fail` will still be `0` and `cmov` will still do nothing. However, if `fail` any value greater than `0`, then some bits of the pre-key value will be overwritten with $z$ according to the bit mask given by `fail`. Ultimately, this means that the behaviour is only the same in the case that the ciphertexts are exactly the same, or differ in at least `0xff` positions. This differing behaviour is clearly a bug as it may allow us to distinguish between cases when the two ciphertexts are the same, only slightly different, or vastly different.

There is another bug, and it occurs in `kyber.py`. Because the server code is quite minimal and we are given a patch for the C library, it might seem innocent. But there is a very suspicious line:

```py
    print('H(pk):', bytes(kyber.sk_buf)[-64:].hex())
```

This gives us the last 64 bytes of the secret key serialisation, which if we look at the KeyGen function, is $H(pk)||z$. This means we have some extra information about the secret key (although not the secret vector itself). We'll see how to use this next.

## Leaking Information

The encapsulation functionality of the server seems useless as we can simply perform that operation ourself using the public key. The goal is secret key recovery, so we need to somehow leak information from decapsulation queries. We are given the result of each decapsulation, but this is just a hash, so we don't necessarily have a decryption oracle. Thinking back to the patch and the fact that we have $z$ however, maybe we do have a way of learning some information about the decryption result...

### The Oracle

The main idea behind our information leaking oracle is that we can distinguish between the case when a ciphertext and its re-encryption during decapsulation is slightly different, or completely different.

Suppose we run encapsulation (locally) to get a ciphertext $c = (\mathbf{u}, v)$ for a generated message $m$. If we pass $c$ to the decapsulation oracle, we expect it to return the correct shared secret; that is, we expect $c$ and the re-encryption to be exactly the same. What happens if we query the decapsulation oracle with $(\mathbf{u}, v+1)$? Because the decryption process can tolerate a bit of error, it is very likely that the decryption result will still be the original message $m$. Because the coins (the randomness used for encryption) depends on $m$, this means that the re-encryption result would be precisely $c$. Therefore, the verification will fail as $c \neq (\mathbf{u}, v+1)$. In fact, in this case we would only expect there to be an inequality in one byte of the two ciphertexts' serialisations.

Now suppose we instead query the decapsulation oracle with $c' = (\mathbf{u}, v+o)$ for some larger integer value $o$. It's entirely possible that decrypting this ciphertext yields a different message (i.e. one that differs by one bit, in this case the bit corresponding to the constant coefficient). If the decrypted message is even slightly different to the original message $m$, then the coins will be different, and so the re-encryption is also very likely to be completely different to $c$. In this case, `fail` is almost certainly going to be `0xff`, and the resulting shared secret will be overwritten with $\mathsf{KDF}(z||H(c'))$. Since we know $z$ and $c'$, we can compute this value and hence determine when this occurs!

So in summary, our oracle allows us to check whether a given _perturbed_ ciphertext decrypts to the same message as the original unperturbed ciphertext. We'll see how powerful this is a bit later.

## Recovering $\mathbf{s}$

Before seeing some more details about how to use the oracle, we try and motivate it a bit. Suppose we have two message/ciphertext pairs $(m_1, (\mathbf{u}_1, v_1))$ and $(m_2, (\mathbf{u}_2, v_2))$. From the decryption equation, we have

$$
\begin{aligned}
    v_1 - \mathbf{s} \cdot \mathbf{u}_1 &= \mathbf{e} \cdot \mathbf{r}_1 + e_{1,2} - \mathbf{s} \cdot \mathbf{e}_{1,1} + \mu_1 \\
    v_2 - \mathbf{s} \cdot \mathbf{u}_2 &= \mathbf{e} \cdot \mathbf{r}_2 + e_{2,2} - \mathbf{s} \cdot \mathbf{e}_{2,1} + \mu_2 \\
\end{aligned}
$$

Writing the combined error terms as $E_1$ and $E_2$:

$$
\begin{aligned}
    v_1 - \mathbf{s} \cdot \mathbf{u}_1 &= E_1 + \mu_1 \\
    v_2 - \mathbf{s} \cdot \mathbf{u}_2 &= E_2 + \mu_2 \\
\end{aligned}
$$

Writing $y_i = v_i - E_i - \mu_i$:

$$
\begin{aligned}
    \mathbf{s} \cdot \mathbf{u}_1 &= y_1 \\
    \mathbf{s} \cdot \mathbf{u}_2 &= y_2 \\
\end{aligned}
$$

Writing $\mathbf{s} = (s_0, s_1)$, $\mathbf{u}_1 = (u_{1,0}, u_{1,1})$, $\mathbf{u}_2 = (u_{2,0}, u_{2,1})$:

$$
\begin{aligned}
    s_0 u_{1, 0} + s_1 u_{1, 1} &= y_1 \\
    s_1 u_{2, 0} + s_1 u_{2, 1} &= y_2 \\
\end{aligned}
$$

And so, solving for $s_0$ and $s_1$, we get

$$
\begin{aligned}
    s_1 &= (y_2 - y_1 u_{1,0}^{-1} u_{2,0})(u_{2,1} - u_{1,0}^{-1} u_{1,1} u_{2,0})^{-1} \\
    s_0 &= (y_1 - s_1 u_{1,1}) u_{1,0}^{-1}
\end{aligned}
$$

But of course, to actually compute this, we need to know $E_1$ and $E_2$, which depend on $\mathbf{s}$! At least now we know that if we can recover these small error terms, we can recover the secret key. So let's see how to do that using the oracle.

## Recovering the Error

Suppose we run the encapsulation function locally to obtain a ciphertext $c = (\mathbf{u}, v)$ for a random message $m$. From the decryption equation, we have

$$
\begin{aligned}
    v - \mathbf{s} \cdot \mathbf{u} &= \mathbf{e} \cdot \mathbf{r} + e_2 - \mathbf{s} \cdot \mathbf{e}_1 + \mu \\
    &= E + \mu
\end{aligned}
$$

Our goal, as established in the previous section, is to recover $E$. The ciphertext polynomial $v$ sits by itself as a term, so any changes to coefficients of $v$ is reflected in the right hand side of this equation. Note that this is possible because the compression on $v$ was removed; otherwise we would lose fine-grained control and the attack may not work.

The coefficients of the message polynomial $\mu$ are either $0$ or $1665$ and the message itself is obtained by running the $\mathsf{Compress}_q$ function on the noisy message polynomial with $d = 1$. Note that

$$
\mathsf{Compress}_q(x, 1) =
\begin{cases}
    \ 1 \qquad \text{for}\ 833 \leq x \leq 2496, \\
    \ 0 \qquad \text{otherwise}
\end{cases}
$$

The idea is to try different integer values of $o$ such that the decryption of $(\mathbf{u}, v + X^i o_i)$ results in a different message to $m$. When this is the case, we know that the combined error from the corresponding $X^i$ coefficient in $E$ (call it $E_i$) and $o_i$ is enough to cause that message bit to flip.

More concretely, consider the case where the $i$th message bit $b_i$ is $0$. If we find an $o_i$ such that $(\mathbf{u}, v + X^i o_i)$ decrypts to a different message to $m$, but $(\mathbf{u}, v + X^i (o_i - 1))$ does decrypt to $m$, then we know that $E_i + o_i = 833$. Therefore, we recover $E_i = 833 - o_i$.

On the other hand, if $b_i$ is $1$ and we find $o_i$ which satisfies this property, then we know that $E_i + o_i + 1665 = 2497$. Therefore, we recover $E_i = 2496 - 1665 - o_i = 832 - o_i$.

We can neatly summarise both cases in the single equation:

$$
E_i = 833 - b_i - o_i
$$

To recover the error polynomial, we simply run this search for each of the $256$ coefficients!

We must also consider the query complexity since we have a limited number of queries. Experiments show that the coefficients in the combined error polynomial can range from as small as $0$ to as large as $150$ or greater in magnitude. Even with a liberal estimate of $50$ queries per coefficient, a naive linear search still requires around $256 \cdot 50 = 12800$ queries. It is necessary to speed this up by implementing the search as a binary search instead. With a binary search approach, we can comfortably recover the coefficients using only around $3500$ queries most of the time.

## Recovering the Flag

With the error polynomials recovered, we can easily recover the secret polynomial vector $\mathbf{s}$ by solving a system of two linear equations as we saw earlier. The hard part of the challenge is more or less done, and all that's left is to XOR the secret with the encrypted flag!

There is one final detail however. Serialising the recovered secret polynomials and XORing the result with the encrypted flag won't work. If we look at the specification, and more specifically the PKE KeyGen algorithm, we see that the secret key is encoded as an element in NTT domain. We've recovered $\mathbf{s}$ in the normal domain, so it is necessary to run the transformation algorithm on it before serialising it. Fortunately, we can just use the `ntt` function provided by the Kyber reference implementation to do this for us.

At last, we get the flag!

## Solve Script

Note that the library is patched to also return the generated message in the encapsulation function.

```diff
diff --git a/ref/kem.c b/ref/kem.c
index f376bd2..2a41974 100644
--- a/ref/kem.c
+++ b/ref/kem.c
@@ -1,4 +1,5 @@
 #include <stddef.h>
+#include <string.h>
 #include <stdint.h>
 #include "params.h"
 #include "kem.h"
@@ -50,7 +51,7 @@ int crypto_kem_keypair(uint8_t *pk,
 **************************************************/
 int crypto_kem_enc(uint8_t *ct,
                    uint8_t *ss,
-                   const uint8_t *pk)
+                   const uint8_t *pk, uint8_t *hm)
 {
   uint8_t buf[2*KYBER_SYMBYTES];
   /* Will contain key, coins */
@@ -59,6 +60,7 @@ int crypto_kem_enc(uint8_t *ct,
   randombytes(buf, KYBER_SYMBYTES);
   /* Don't release system RNG output */
   hash_h(buf, buf, KYBER_SYMBYTES);
+  memcpy(hm, buf, KYBER_SYMBYTES);

   /* Multitarget countermeasure for coins + contributory KEM */
   hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
diff --git a/ref/kem.h b/ref/kem.h
index 3f3eff6..50bb7e5 100644
--- a/ref/kem.h
+++ b/ref/kem.h
@@ -33,7 +33,7 @@
 int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

 #define crypto_kem_enc KYBER_NAMESPACE(enc)
-int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
+int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, uint8_t *hm);

 #define crypto_kem_dec KYBER_NAMESPACE(dec)
 int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

### `kyber_util.py`

```py
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
```

### `solv.sage`

```py
from pwn import *
from kyber_util import *
import time
import ctypes
import hashlib

q = 3329
F = GF(q)
P.<X> = PolynomialRing(F)
R.<Xbar> = P.quotient_ring(X^256 + 1)

ORACLE_QUERIES = 0
def oracle(z, ct):
    global ORACLE_QUERIES
    ORACLE_QUERIES += 1
    conn.sendlineafter(b'> ', b'dec ' + ct.hex().encode())
    ss = conn.recvline().decode().strip().split('ss: ')[1]
    expected_ss_if_different = kdf(z + hash_h(ct)).hex()
    return ss == expected_ss_if_different

def recover_error_coefficient(z, ct, hm, idx):
    lower = 0
    upper = 1200
    v = bytes_to_poly(ct[-384:])
    while lower <= upper:
        middle = (upper + lower) // 2
        v_ = v + middle * Xbar^idx
        v_ = poly_to_bytes(v_)
        r = oracle(z, ct[:-384] + v_)
        if r:
            v_ = v + (middle - 1) * Xbar^idx
            v_ = poly_to_bytes(v_)
            r = oracle(z, ct[:-384] + v_)
            if not r:
                b = (hm[idx // 8] >> (idx % 8)) & 1
                return 833 - b - middle
            else:
                upper = middle - 1
        else:
            lower = middle + 1

def recover_error_polynomial(z, ct, hm):
    coeffs = []
    for i in range(256):
        c = recover_error_coefficient(z, ct, hm, i)
        coeffs.append(c)
    return R(coeffs)

conn = remote('0.0.0.0', 1337)
pk = bytes.fromhex(conn.recvline().decode().strip().split('pk: ')[1])
hpk = bytes.fromhex(conn.recvline().decode().strip().split('H(pk): ')[1])
z = hpk[-32:]

ct1, _, hm1 = kem_enc(pk)
ct2, _, hm2 = kem_enc(pk)

timer_start = time.time()
E1 = recover_error_polynomial(z, ct1, hm1)
print(f'[!] used {ORACLE_QUERIES} in {time.time() - timer_start:.2f}s to recover E1: {list(E1)}')
timer_start = time.time()
E2 = recover_error_polynomial(z, ct2, hm2)
print(f'[!] used total {ORACLE_QUERIES} in {time.time() - timer_start:.2f}s to recover E2: {list(E2)}')

u1 = compressed_bytes_to_polyvec(ct1[:640])
v1 = bytes_to_poly(ct1[-384:])
m1 = poly_frommsg(hm1)
y1 = v1 - E1 - m1

u2 = compressed_bytes_to_polyvec(ct2[:640])
v2 = bytes_to_poly(ct2[-384:])
m2 = poly_frommsg(hm2)
y2 = v2 - E2 - m2

s1 = (y2 - y1 * u1[0]^-1 * u2[0]) * (u2[1] - u1[0]^-1 * u1[1] * u2[0])^-1
s0 = (y1 - s1 * u1[1]) * u1[0]^-1
s = vector(R, [s0, s1])
print(f'[+] recovered secret key:', list(s[0]), list(s[1]))
s = (ctypes.c_int16 * int(2 * 256))(*(list(s[0]) + list(s[1])))
kyber_lib.pqcrystals_kyber512_ref_polyvec_ntt(s)
s = vector(R, [R(s[:256]), R(s[256:])])
s_bytes = polyvec_to_bytes(s)

conn.sendlineafter(b'> ', b'hax')
flag_enc = bytes.fromhex(conn.recvline().decode().strip().split('flag_enc: ')[1])
flag = xor(flag_enc, s_bytes[:len(flag_enc)])
print(flag.decode())
```
