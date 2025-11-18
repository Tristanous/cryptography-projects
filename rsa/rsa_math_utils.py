"""
- gcd, egcd, invmod
- racine entière n-ième
- test de carré parfait
- théorème chinois des restes (CRT)

Utilisation comme module :
    from rsa_math_utils import invmod, crt, int_nth_root
    d = invmod(e, phi)
    x, m = crt([c1, c2], [n1, n2])
"""

from math import isqrt
from typing import List, Tuple


def gcd(a,b):
    while b:
        a, b = b, a % b
    return abs(a)


def egcd(a,b):
    if b == 0:
        return abs(a), 1 if a > 0 else -1, 0
    x0, y0 = 1, 0
    x1, y1 = 0, 1
    aa, bb = a, b
    while bb:
        q = aa // bb
        aa, bb = bb, aa - q * bb
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return abs(aa), x0, y0


def invmod(a,m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("inverse modulaire inexistant")
    return x % m


def is_square(n):
    if n < 0:
        return False
    r = isqrt(n)
    return r * r == n


def crt(remainders,moduli):
    if len(remainders) != len(moduli):
        raise ValueError("longueurs différentes")
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        inv = invmod(Mi, m)
        x = (x + r * Mi * inv) % M
    return x, M


def int_nth_root(x,n):
    if x < 0 and n % 2 == 0:
        raise ValueError("racine paire d'un nombre négatif")
    if x == 0:
        return 0, True
    if x == 1:
        return 1, True
    g = int(round(x ** (1.0 / n)))
    if g <= 0:
        g = 1
    while True:
        t = ((n - 1) * g + x // (g ** (n - 1))) // n
        if t >= g:
            break
        g = t
    while (g + 1) ** n <= x:
        g += 1
    while g ** n > x:
        g -= 1
    return g, g ** n == x
