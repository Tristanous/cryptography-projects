# Cryptography Projects

This repository is a personal playground for classical and modern cryptography:

- CTF challenges i've made
- Reusable tooling for encoding/decoding and RSA
- Implementations of lattice-based / post-quantum schemes
- A small Sage toolbox for lattice attacks


---

## Repository structure

```text
├── challs/           # CTF challenges + writeups
├── encodage/         # Encoding / decoding helpers
├── lattices/         # Sage lattice utilities (LLL, Coppersmith, etc.)
├── post-quantum/     # Toy post-quantum schemes (Kyber, Dilithium, SPHINCS…)
├── rsa/              # RSA toolbox (factoring, Wiener, common modulus…)
└── README.md
```

---

## `challs/` – CTF challenges

This folder contains CTF challenges i've made for the NBCTF.

---

## `encodage/` – Encoding & auto-detection

Helpers for classic CTF encoding tasks.

### `encodage/encode_decode.py`

Supported formats:

* `text` – UTF-8 text
* `hex` – hexadecimal
* `base64` / `base32`
* `bin` – binary strings 
* `url` – URL / percent encoding
* `rot` – ROT-N on ASCII letters
* `dec` – base-10 integer representation

Usage :

```python
from encodage.encode_decode import convert_str

hex_value = convert_str("text", "hex", "hello")
text_value = convert_str("hex", "text", "666c61677b746573747d")
dec_value = convert_str("hex", "dec", "ff")  
```

### `encodage/auto_detect_encoding.py`

* Tests multiple candidates: raw text, hex, base64/base32, binary, URL encoding, ROT-N…
* Scores outputs based on:

  * Ratio of printable characters, letters, spaces
* Returns the top candidates with:

  * inferred source format
  * optional extra info (e.g. `ROT=13`)
  * decoded text

Example usage:

```python
from encodage.auto_detect_encoding import detect_encodings

cands = detect_encodings("ZmxhZ3t0ZXN0fQ==")
best = cands[0]
print(best.source_fmt, best.extra_info, best.decoded_text)
```

---

## `lattices/` – Lattice tools for CTF (Sage)

### `lattices/lattice_attacks.sage`

A Sage script with basic building blocks for lattice attacks:

* `lll_reduce_basis(rows)` – run LLL on a basis of ℤⁿ and return the reduced basis
* `shortest_vector(rows)` – get a short vector via LLL
* `coppersmith_univariate(f, X, beta, epsilon)` – wrapper around Sage’s `small_roots` for univariate Coppersmith
* `coppersmith_partial_p(N, p_high, bits_low, ...)` – attack to recover RSA prime `p` when some top bits are known

Usage inside Sage:

```python
load("lattices/lattice_attacks.sage")

B = [[1, 0, 0],
     [0, 2, 1],
     [0, 1, 2]]

print(lll_reduce_basis(B))
print(shortest_vector(B))
```


---

## `post-quantum/` – Post-quantum schemes

This folder contains **simplified, educational implementations** of common post-quantum primitives.
They are not parameter-correct, not constant-time, and not safe for real use.

### `post-quantum/kyber.py`

A heavily simplified KEM inspired by **CRYSTALS-Kyber**:

* Implements:

  * A `Polynomial` class with add/sub/mul (naïve) + compression
  * `KyberImplementation` with `keygen`, `encaps`, `decaps`
* Shows the structure:

  * public matrix `A`
  * secrets `s`, errors `e`
  * `t = A * s + e`
  * encapsulation = new noise + encode shared seed into a polynomial


### `post-quantum/dilithium.py`

Toy signature scheme inspired by **CRYSTALS-Dilithium**:

* Work in polynomial rings modulo Q and ( X^N + 1 )
* `DilithiumImplementation` with:

  * `keygen()` – generate matrix `A`, small secrets `s1`, `s2`, public `t = A*s1 + s2`
  * `sign(message, sk)` – Fiat-Shamir with aborts:

    * sample `y`, compute `w = A*y`
    * hash `(message || w)` to get challenge `c`
    * compute `z = y + c*s1`, enforce norm bounds
  * `verify(message, signature, pk)` – replay challenge and consistency checks

This mirrors the high-level idea of Dilithium, but omits many subtleties (hints, exact bounds, etc.).

### `post-quantum/SPHINCS+.py`

Simplified **SPHINCS-like** hash-based signature:

* Implements a mini variant with:

  * `WOTS` (Winternitz One-Time Signature):

    * `keygen`, `sign`, `verify_from_sig`
  * `SPHINCS_Simple`:

    * A single Merkle tree over WOTS public keys
    * `keygen()` – build tree and public root
    * `sign(msg)` – choose a leaf, sign with WOTS, add auth path
    * `verify(msg, sig, pub_root)` – reconstruct leaf and walk up the Merkle tree

Captures the core SPHINCS idea: WOTS + Merkle tree, with greatly reduced complexity.

### `post-quantum/lamport_ots.py`

Classic **Lamport One-Time Signature**:

* `lamport_keygen()` – generate one-time signing key and verification key
* `lamport_sign(sk, message)` – pick one value per hash bit
* `lamport_verify(pk, message, sig)` – verify by hashing back

This is a genuinely post-quantum-secure (but one-time) signature scheme.

### `post-quantum/lwe_kem.py`

A **toy LWE-based KEM** (not secure, parameters tiny):

* Shows the typical KEM structure:

  * `lwe_keygen()` – sample secret and public `a, b`
  * `lwe_encaps(pk)` – create ciphertext and shared key
  * `lwe_decaps(sk, ct)` – recover the key


---

## `rsa/` – RSA toolbox

A collection of small scripts for common RSA attacks in CTFs.

### `rsa/rsa_math_utils.py`

Basic number-theory helpers:

* `gcd`, `egcd`, `invmod`
* `is_square`
* `crt(remainders, moduli)` – Chinese Remainder Theorem
* `int_nth_root(x, n)` – integer n-th root + exactness flag


### `rsa/rsa_factor_small.py`

Implements multiple methods:

* Trial division
* Fermat factoring
* Pollard’s ρ
* Pollard’s p−1
* ECM stage-1 (elliptic curve method)
* Simple Quadratic Sieve variant

Exports:

* `factor_semiprime(n)` – try all methods to factor `n ≈ p*q`
* `factor_full(n)` – recursively factor `n` until you get a list of “prime-ish” factors


### `rsa/rsa_common_modulus.py`

Attack for **common modulus** RSA:

* Scenario: same modulus `n`, different exponents `e1`, `e2`, ciphertexts `c1`, `c2` of the same message.
* `common_modulus_attack(n, e1, e2, c1, c2)` – reconstructs the original message `m` using extended GCD and modular inverses.

### `rsa/rsa_low_exponent.py`

Helpers for **low-exponent** attacks:

* `low_exponent_single(c, e, n)` – if `m^e < n` with no padding, take integer `e`-th root
* `low_exponent_broadcast(ciphertexts, moduli, e)` – Coppersmith-style broadcast for small `e` with multiple moduli and same message

Useful for RSA with `e=3` and poor padding.

### `rsa/rsa_wiener.py`

**Wiener attack** implementation:

* `wiener_attack(e, n)` – recover a small private exponent `d` when RSA is misconfigured

  * Returns `(d, p, q)` if the attack succeeds, otherwise `None`.

### `rsa/rsa_decrypt.py`

RSA glue functions:

* Conversions:

  * `int_to_bytes`, `bytes_to_int`
* Core operations:

  * `rsa_encrypt_int(m, e, n)`
  * `rsa_decrypt_int(c, d, n)`
  * `rsa_decrypt_with_factors(c, p, q, e)`
* High-level helpers:

  * `decrypt_int_to_bytes(c, d, n)`
  * `decrypt_int_to_str(c, d, n, encoding="utf-8")`
  * `encrypt_str_to_int(s, e, n)`
  * `decrypt_with_factors_to_str(c, p, q, e)`

