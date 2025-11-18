"""
Implémentation simple d'un schéma de signature Lamport One-Time Signature (OTS).
C'est un schéma de signature post-quantique basé sur les fonctions de hachage.

Utilisation comme module :
    from lamport_ots import lamport_keygen, lamport_sign, lamport_verify

    sk, pk = lamport_keygen()
    sig = lamport_sign(sk, b"message")
    ok = lamport_verify(pk, b"message", sig)
"""

import os
import hashlib


L = 256
N = 32


def H(x):
    return hashlib.sha256(x).digest()


def lamport_keygen():
    sk = []
    pk = []
    for _ in range(L):
        x0 = os.urandom(N)
        x1 = os.urandom(N)
        sk.append((x0, x1))
        pk.append((H(x0), H(x1)))
    return sk, pk


def lamport_sign(sk, message):
    h = H(message)
    sig = []
    for i in range(L):
        bit = (h[i // 8] >> (7 - (i % 8))) & 1
        sig.append(sk[i][bit])
    return sig


def lamport_verify(pk, message, sig):
    if len(sig) != L or len(pk) != L:
        return False
    h = H(message)
    for i in range(L):
        bit = (h[i // 8] >> (7 - (i % 8))) & 1
        y = sig[i]
        if H(y) != pk[i][bit]:
            return False
    return True


if __name__ == "__main__":
    sk, pk = lamport_keygen()
    msg = b"flag{lamport_test}"
    sig = lamport_sign(sk, msg)
    print(lamport_verify(pk, msg, sig))
