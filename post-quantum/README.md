# Post-Quantum Cryptography – Learning Implementations

This directory contains **simplified implementations of post-quantum cryptographic schemes**.

The main goal is to **learn and understand**:

- the principles behind modern post-quantum algorithms,
- how the building blocks (polynomials, lattices, hash trees, noise, etc.) fit together,
- what the high-level structure of these schemes looks like in code.


---

## Files overview

```text
post-quantum/
├── kyber.py
├── dilithium.py
├── SPHINCS+.py
├── lamport_ots.py
└── lwe_kem.py
````

---

## `kyber.py` – Kyber-style KEM (lattice-based)

A simplified key encapsulation mechanism inspired by CRYSTALS-Kyber.

Concepts illustrated:

* Working in a polynomial ring of the form Z_q[X] / (X^N + 1)
* Representing polynomials and supporting:

  * addition, subtraction, multiplication modulo a polynomial and modulo q
* Building a public matrix A and secret vectors:

  * t = A * s + e, where s and e are small “error” polynomials
* Encapsulation and decapsulation:

  * encapsulation creates a ciphertext and a shared secret
  * decapsulation recovers the same shared secret from the ciphertext and the secret key


---

## `dilithium.py` – Dilithium-style digital signatures

A simplified digital signature scheme inspired by CRYSTALS-Dilithium.

Concepts illustrated:

* Vectors and matrices of polynomials modulo q and modulo X^N + 1
* Secret vectors s1 and s2 with small coefficients
* Public key t = A * s1 + s2
* Fiat–Shamir with aborts:

  * sampling a random masking vector y
  * computing w = A * y
  * deriving a challenge c from a hash of the message and w
  * forming z = y + c * s1 and enforcing bounds on the coefficients
* Verification by reconstructing an approximation of w from z, c and the public key and checking consistency with a new challenge

---

## `SPHINCS+.py` – SPHINCS-like hash-based signatures

A simplified, single-tree version inspired by SPHINCS+, a stateless hash-based signature scheme.

Concepts illustrated:

* **WOTS (Winternitz One-Time Signature)**:

  * representing a message hash in base W
  * building chains of repeated hashing starting from secret values
  * deriving a public key from fully hashed chains
* **Merkle trees** over WOTS public keys:

  * each leaf is a compressed WOTS public key
  * the global public key is the root of the Merkle tree
* Signing:

  * signing a message hash with a WOTS secret key at some leaf
  * providing the Merkle authentication path
* Verification:

  * reconstructing the WOTS public key from the WOTS signature and the message hash
  * walking up the Merkle tree using the authentication path to recover the root and compare it to the public key

---

## `lamport_ots.py` – Lamport one-time signatures

An implementation of Lamport’s one-time signature scheme.

Concepts illustrated:

* Secret key as pairs of random values
* Public key as hashes of all secret values
* Signing by revealing one value from each pair according to the bits of the message hash
* Verification by hashing the revealed values and comparing them to the corresponding public key entries

---

## `lwe_kem.py` – LWE-inspired KEM

A minimal key encapsulation mechanism inspired by constructions based on LWE (Learning With Errors).

Concepts illustrated:

* Sampling secrets and errors modulo an integer q
* Using noisy linear relations of the form a * s + e (mod q)
* Public keys that encode such relations
* Encapsulation producing:

  * a ciphertext derived from the public key, secret randomness and noise
  * a shared secret key derived from a small message
* Decapsulation using the secret key to remove the noise and recover the same shared secret

---


## Limitations:

* Parameters are simplified and do not match official standards.
* No focus on side-channel resistance or constant-time behavior.
