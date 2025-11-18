"""
Attaque "common modulus" RSA :
- même n, exposants e1 et e2 différents, messages chiffrés c1 et c2
- suppose gcd(e1, e2) == 1
- reconstruit le message m à partir de n, e1, e2, c1, c2

Utilisation comme module :
    from rsa_common_modulus import common_modulus_attack
    m = common_modulus_attack(n, e1, e2, c1, c2)
"""

from rsa_math_utils import egcd, invmod


def common_modulus_attack(n, e1, e2, c1, c2):
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1 et e2 ne sont pas premiers entre eux")
    if s1 < 0:
        c1_inv = invmod(c1, n)
        part1 = pow(c1_inv, -s1, n)
    else:
        part1 = pow(c1, s1, n)
    if s2 < 0:
        c2_inv = invmod(c2, n)
        part2 = pow(c2_inv, -s2, n)
    else:
        part2 = pow(c2, s2, n)
    return (part1 * part2) % n
