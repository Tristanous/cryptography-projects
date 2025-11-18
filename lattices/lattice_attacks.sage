"""
lattice_attacks.sage

Outils de base pour attaques par réseaux avec Sage :
- lll_reduce_basis : réduction LLL d'une base de Z^n
- shortest_vector  : vecteur court issu de LLL
- coppersmith_univariate : Coppersmith univarié via small_roots de Sage
- coppersmith_partial_p  : récupération d'un facteur RSA p quand on connaît ses bits hauts

Utilisation dans Sage :

    load("lattice_attacks.sage")

    # LLL simple
    B = [[1, 0, 0],
         [0, 2, 1],
         [0, 1, 2]]
    L = lll_reduce_basis(B)
    v = shortest_vector(B)

    # Coppersmith univarié
    N = ...
    R.<x> = PolynomialRing(Zmod(N))
    f = x^2 + a*x + b
    roots = coppersmith_univariate(f, X=2^40)

    # Coppersmith partiel sur p :
    # on suppose p = p_high + x, avec |x| < 2^bits_low
    # p_high doit déjà inclure le shift (p_high * 2^bits_low si besoin)
    N = ...
    p_high = ...
    bits_low = 64
    p = coppersmith_partial_p(N, p_high, bits_low)
"""

def lll_reduce_basis(rows):
    M = matrix(ZZ, rows)
    R = M.LLL()
    return [list(R.row(i)) for i in range(R.nrows())]


def shortest_vector(rows):
    M = matrix(ZZ, rows)
    R = M.LLL()
    v = R.row(0)
    return list(v)


def coppersmith_univariate(f, X, beta=1, epsilon=None):
    if epsilon is None:
        epsilon = QQ(1) / 8
    roots = f.small_roots(X=X, beta=beta, epsilon=epsilon)
    return [ZZ(r) for r in roots]


def coppersmith_partial_p(N, p_high, bits_low, beta=1, epsilon=None):
    if epsilon is None:
        epsilon = QQ(1) / 8
    R = PolynomialRing(Zmod(N), "x")
    x = R.gen()
    f = p_high + x
    X = 2^bits_low
    roots = f.small_roots(X=X, beta=beta, epsilon=epsilon)
    if not roots:
        return None
    x0 = ZZ(roots[0])
    return p_high + x0
