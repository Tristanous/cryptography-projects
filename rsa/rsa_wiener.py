"""
Implémentation de l'attaque de Wiener sur RSA :
- récupère d quand il est trop petit par rapport à n
- retourne (d, p, q) si l'attaque réussit, sinon None

Utilisation comme module :
    from rsa_wiener import wiener_attack
    res = wiener_attack(e, n)
    if res:
        d, p, q = res
"""

from math import isqrt

from rsa_math_utils import is_square


def continued_fraction(n, d):
    cf = []
    while d:
        a = n // d
        cf.append(a)
        n, d = d, n - a * d
    return cf


def convergents(cf):
    num1, num2 = 1, 0
    den1, den2 = 0, 1
    for a in cf:
        num = a * num1 + num2
        den = a * den1 + den2
        yield num, den
        num2, num1 = num1, num
        den2, den1 = den1, den


def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0 or not is_square(disc):
            continue
        t = isqrt(disc)
        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == n:
            return d, p, q
    return None
