"""
- low_exponent_single : cas m^e < n, racine entière directe de c
- low_exponent_broadcast : même message m chiffré avec même e et plusieurs moduli n_i

Utilisation comme module :
    from rsa_low_exponent import low_exponent_single, low_exponent_broadcast
    m1 = low_exponent_single(c, e, n)
    m2 = low_exponent_broadcast([c1, c2, c3], [n1, n2, n3], e)
"""

from rsa_math_utils import crt, int_nth_root


def low_exponent_single(c, e, n):
    m, exact = int_nth_root(c, e)
    if exact and m**e < n:
        return m
    return None


def low_exponent_broadcast(ciphertexts, moduli, e):
    x, _ = crt(ciphertexts, moduli)
    m, exact = int_nth_root(x, e)
    if not exact:
        raise ValueError("racine non exacte dans l'attaque broadcast")
    return m
