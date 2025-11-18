"""
Outils de base pour chiffrer/déchiffrer RSA :
- rsa_encrypt_int / rsa_decrypt_int sur entiers
- conversion int <-> bytes <-> str
- déchiffrement à partir de (n, d) ou de (p, q, e)

Utilisation comme module :
    from rsa_decrypt import rsa_decrypt_int, decrypt_int_to_str, encrypt_str_to_int

    m = rsa_decrypt_int(c, d, n)
    s = decrypt_int_to_str(c, d, n)
    c2 = encrypt_str_to_int("flag{test}", e, n)
"""

from rsa_math_utils import invmod


def int_to_bytes(x):
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def rsa_encrypt_int(m, e, n):
    return pow(m, e, n)


def rsa_decrypt_int(c, d, n):
    return pow(c, d, n)


def rsa_decrypt_with_factors(c, p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = invmod(e, phi)
    return pow(c, d, n)


def decrypt_int_to_bytes(c, d, n):
    m = rsa_decrypt_int(c, d, n)
    return int_to_bytes(m)


def decrypt_int_to_str(c, d, n, encoding="utf-8", errors="ignore"):
    b = decrypt_int_to_bytes(c, d, n)
    return b.decode(encoding, errors=errors)


def encrypt_str_to_int(s, e, n, encoding="utf-8"):
    b = s.encode(encoding)
    m = bytes_to_int(b)
    return rsa_encrypt_int(m, e, n)


def decrypt_with_factors_to_str(c, p, q, e, encoding="utf-8", errors="ignore"):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = invmod(e, phi)
    b = int_to_bytes(pow(c, d, n))
    return b.decode(encoding, errors=errors)
