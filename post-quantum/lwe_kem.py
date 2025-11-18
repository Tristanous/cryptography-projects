"""
KEM basé sur LWE (Learning With Errors).

Structure type :
- keygen()   -> (pk, sk)
- encaps(pk) -> (ct, K)
- decaps(sk, ct) -> K'

Utilisation comme module :
    from toy_lwe_kem import lwe_keygen, lwe_encaps, lwe_decaps

    pk, sk = lwe_keygen()
    ct, K  = lwe_encaps(pk)
    K2     = lwe_decaps(sk, ct)
"""

import secrets
import hashlib


Q = 4099
NOISE_BOUND = 3


def H(x):
    return hashlib.sha256(x).digest()


def sample_uniform():
    return secrets.randbelow(Q)


def sample_noise():
    return secrets.randbelow(2 * NOISE_BOUND + 1) - NOISE_BOUND


def lwe_keygen():
    a = sample_uniform()
    s = sample_noise()
    e = sample_noise()
    b = (a * s + e) % Q
    pk = (a, b)
    sk = s
    return pk, sk


def lwe_encaps(pk):
    a, b = pk
    r = sample_noise()
    e1 = sample_noise()
    e2 = sample_noise()
    m = secrets.randbelow(2)
    u = (a * r + e1) % Q
    v = (b * r + e2 + (Q // 2) * m) % Q
    ct = (u, v)
    K = H(bytes([m]))
    return ct, K


def lwe_decaps(sk, ct):
    s = sk
    u, v = ct
    t = (v - u * s) % Q
    d0 = min(t, Q - t)
    d1 = min((t - Q // 2) % Q, (Q - (t - Q // 2) % Q) % Q)
    if d0 <= d1:
        m = 0
    else:
        m = 1
    K = H(bytes([m]))
    return K


if __name__ == "__main__":
    pk, sk = lwe_keygen()
    ct, K1 = lwe_encaps(pk)
    K2 = lwe_decaps(sk, ct)
    print(K1 == K2)
