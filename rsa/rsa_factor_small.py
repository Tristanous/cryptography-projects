"""
Méthodes de factorisation RSA :
- division d'essai
- factorisation de Fermat (p et q proches)
- Pollard Rho
- Pollard p-1
- factorisation par courbes elliptiques (ECM, stage 1 simple)
- factorisation d'un semi-produit n = p * q
- factorisation complète en facteurs "premiers" avec factor_full

Utilisation comme module :
    from rsa_factor_small import factor_semiprime, factor_full
    p, q = factor_semiprime(n)
    factors = factor_full(n)
"""

from math import isqrt
import random

from rsa_math_utils import gcd, is_square, egcd


def trial_division(n, limit=None):
    if n % 2 == 0:
        return 2
    if limit is None:
        limit = isqrt(n)
    f = 3
    while f <= limit:
        if n % f == 0:
            return f
        f += 2
    return None


def fermat_factor(n, max_iterations=10**6):
    if n % 2 == 0:
        return None
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iterations):
        b2 = a * a - n
        if is_square(b2):
            b = isqrt(b2)
            p = a - b
            q = a + b
            if p * q == n:
                return min(p, q), max(p, q)
        a += 1
    return None


def pollard_rho(n, max_iterations=10**6):
    if n % 2 == 0:
        return 2
    x = 2
    y = 2
    c = 1
    d = 1
    for _ in range(max_iterations):
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
        if d == n:
            return None
        if d > 1:
            return d
    return None


def generate_primes(limit):
    if limit < 2:
        return []
    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False
    i = 2
    while i * i <= limit:
        if sieve[i]:
            step = i
            start = i * i
            sieve[start : limit + 1 : step] = [False] * (((limit - start) // step) + 1)
        i += 1
    return [p for p, v in enumerate(sieve) if v]


def pollard_pminus1(n, B1=100000):
    if n % 2 == 0:
        return 2
    a = 2
    primes = generate_primes(B1)
    for p in primes:
        k = p
        while k * p <= B1:
            k *= p
        a = pow(a, k, n)
    d = gcd(a - 1, n)
    if 1 < d < n:
        return d
    return None


def ec_add(P, Q, a, n):
    if P is None:
        return Q, 1
    if Q is None:
        return P, 1
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % n == 0:
        return None, 1
    num = (y2 - y1) % n
    den = (x2 - x1) % n
    g, inv, _ = egcd(den, n)
    if g != 1:
        return P, g
    lam = (num * inv) % n
    x3 = (lam * lam - x1 - x2) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3), 1


def ec_double(P, a, n):
    if P is None:
        return None, 1
    x1, y1 = P
    if y1 % n == 0:
        return None, 1
    num = (3 * x1 * x1 + a) % n
    den = (2 * y1) % n
    g, inv, _ = egcd(den, n)
    if g != 1:
        return P, g
    lam = (num * inv) % n
    x3 = (lam * lam - 2 * x1) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3), 1


def ec_scalar_mult(k, P, a, n):
    R = None
    Q = P
    d = 1
    while k > 0:
        if k & 1:
            R, d = ec_add(R, Q, a, n)
            if d > 1 and d < n:
                return None, d
        Q, d = ec_double(Q, a, n)
        if d > 1 and d < n:
            return None, d
        k >>= 1
    return R, 1


def ecm_factor(n, B1=2000, max_curves=20):
    if n % 2 == 0:
        return 2
    primes = generate_primes(B1)
    for _ in range(max_curves):
        x = random.randrange(2, n - 1)
        y = random.randrange(2, n - 1)
        a = random.randrange(2, n - 1)
        b = (y * y - x * x * x - a * x) % n
        disc = (4 * a * a * a + 27 * b * b) % n
        if disc == 0:
            continue
        P = (x, y)
        for p in primes:
            k = p
            while k * p <= B1:
                k *= p
            if k <= 1:
                continue
            P, d = ec_scalar_mult(k, P, a, n)
            if d > 1 and d < n:
                return d
            if P is None:
                break
    return None


def factor_semiprime(n):
    f = trial_division(n)
    if f is not None and f != 1 and f != n:
        return min(f, n // f), max(f, n // f)
    r = fermat_factor(n)
    if r is not None:
        return r
    f = pollard_rho(n)
    if f is not None and f != 1 and f != n:
        return min(f, n // f), max(f, n // f)
    f = pollard_pminus1(n)
    if f is not None and f != 1 and f != n:
        return min(f, n // f), max(f, n // f)
    f = ecm_factor(n)
    if f is not None and f != 1 and f != n:
        return min(f, n // f), max(f, n // f)
    raise ValueError("factorisation échouée")


def factor_full(n):
    if n <= 1:
        return []
    try:
        p, q = factor_semiprime(n)
    except ValueError:
        return [n]
    return sorted(factor_full(p) + factor_full(q))
