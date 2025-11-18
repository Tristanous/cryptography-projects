"""
encode_decode.py

Module de conversion entre formats classiques.

Formats supportés:
- "text"   : texte UTF-8
- "hex"    : représentation hexadécimale
- "base64" : Base64 standard
- "base32" : Base32 standard
- "bin"    : binaire, 8 bits par octet
- "url"    : URL-encoding (percent-encoding)
- "rot"    : ROT-N sur les lettres A-Z / a-z
- "dec"    : entier base 10, interprété comme entier non signé

Utilisation comme module :
    from encode_decode import convert_str
    result = convert_str("text", "hex", "hello", rot_n=13)

Exemple base 10 :
    from encode_decode import convert_str
    dec_val = convert_str("hex", "dec", "ff")      # "255"
    hex_val = convert_str("dec", "hex", "255")     # "ff"
"""

import base64
import urllib.parse


SUPPORTED_FORMATS = ["text", "hex", "base64", "base32", "bin", "url", "rot", "dec"]


def apply_rot(text, shift):
    result = []
    shift = shift % 26
    for ch in text:
        if "a" <= ch <= "z":
            base = ord("a")
            result.append(chr(base + (ord(ch) - base + shift) % 26))
        elif "A" <= ch <= "Z":
            base = ord("A")
            result.append(chr(base + (ord(ch) - base + shift) % 26))
        else:
            result.append(ch)
    return "".join(result)


def to_bytes(source_fmt, data):
    if source_fmt == "text":
        return data.encode("utf-8")

    if source_fmt == "hex":
        cleaned = "".join(data.split())
        return bytes.fromhex(cleaned)

    if source_fmt == "base64":
        return base64.b64decode(data, validate=False)

    if source_fmt == "base32":
        return base64.b32decode(data, casefold=True)

    if source_fmt == "bin":
        bits = "".join(data.split())
        if len(bits) % 8 != 0:
            raise ValueError("Longueur binaire non multiple de 8.")
        return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))

    if source_fmt == "url":
        return urllib.parse.unquote_to_bytes(data)

    if source_fmt == "dec":
        n = int(data, 10)
        if n < 0:
            raise ValueError("Le format 'dec' ne supporte pas les valeurs négatives.")
        if n == 0:
            return b"\x00"
        length = (n.bit_length() + 7) // 8
        return n.to_bytes(length, "big")

    raise ValueError(f"Format source non supporté: {source_fmt}")


def from_bytes(target_fmt, b, rot_n):
    if target_fmt == "text":
        return b.decode("utf-8", errors="replace")

    if target_fmt == "hex":
        return b.hex()

    if target_fmt == "base64":
        return base64.b64encode(b).decode("ascii")

    if target_fmt == "base32":
        return base64.b32encode(b).decode("ascii")

    if target_fmt == "bin":
        return "".join(f"{byte:08b}" for byte in b)

    if target_fmt == "url":
        return urllib.parse.quote_from_bytes(b)

    if target_fmt == "rot":
        text = b.decode("utf-8", errors="replace")
        return apply_rot(text, rot_n)

    if target_fmt == "dec":
        n = int.from_bytes(b, "big", signed=False)
        return str(n)

    raise ValueError(f"Format cible non supporté: {target_fmt}")


def convert(source_fmt, target_fmt, data, rot_n=13):
    if source_fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Format source non supporté: {source_fmt}")
    if target_fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Format cible non supporté: {target_fmt}")

    if source_fmt == "rot":
        data = apply_rot(data, -rot_n)
        source_fmt_effective = "text"
    else:
        source_fmt_effective = source_fmt

    b = to_bytes(source_fmt_effective, data)
    return from_bytes(target_fmt, b, rot_n)


def convert_str(source_fmt, target_fmt, data, rot_n=13):
    return convert(source_fmt, target_fmt, data, rot_n=rot_n)


if __name__ == "__main__":
    SOURCE_FORMAT = "hex"
    TARGET_FORMAT = "dec"
    DATA = "ff"
    ROT_SHIFT = 13

    result = convert_str(SOURCE_FORMAT, TARGET_FORMAT, DATA, rot_n=ROT_SHIFT)
    print(result)
