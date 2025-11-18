"""
Essaye de deviner l'encodage / format d'une chaîne.
Il réutilise encode_decode.py :

Formats supportés :
- text
- hex
- base64
- base32
- bin
- url
- rot

Résultat : une liste de candidats avec :
- format source
- info supplémentaire (ex: ROT=13)
- texte décodé
- score

Utilisation comme module :
    from auto_detect_encoding import detect_encodings
    best = detect_encodings("ZmxhZ3t0ZXN0fQ==")[0].decoded_text

"""
import string
from dataclasses import dataclass
from typing import List, Optional
from encodage.encode_decode import convert_str

@dataclass
class Candidate:
    source_fmt: str          # "hex", "base64", "rot", "text", etc.
    decoded_text: str        # texte supposé en clair
    score: float             # score heuristique
    extra_info: Optional[str] = None  # ex: "ROT=13"

def hex(s: str) -> bool:
    s_clean = "".join(s.split())
    if len(s_clean) < 2 or len(s_clean) % 2 != 0:
        return False
    allowed = set("0123456789abcdefABCDEF")
    return all(c in allowed for c in s_clean)

def b64(s):
    s_clean = s.strip()
    if len(s_clean) < 4 or len(s_clean) % 4 != 0:
        return False
    allowed = set(string.ascii_letters + string.digits + "+/=")
    return all(c in allowed for c in s_clean)

def b32(s):
    s_clean = s.strip().replace("=", "")
    if len(s_clean) < 2:
        return False
    allowed = set(string.ascii_uppercase + "234567")
    s_upper = s_clean.upper()
    return all(c in allowed for c in s_upper)

def bin(s):
    bits = "".join(s.split())
    if not bits:
        return False
    if any(c not in "01" for c in bits):
        return False
    return len(bits) % 8 == 0

def url(s):
    if "%" in s:
        count_valid = 0
        count_total = 0
        i = 0
        while i < len(s):
            if s[i] == "%" and i + 2 < len(s):
                count_total += 1
                h = s[i + 1 : i + 3]
                if all(c in "0123456789abcdefABCDEF" for c in h):
                    count_valid += 1
                i += 3
            else:
                i += 1
        if count_total > 0 and count_valid / count_total > 0.6:
            return True
    if "+" in s:
        return True
    return False

def rot(s):
    letters = sum(c.isalpha() for c in s)
    return letters >= max(3, len(s) // 3)

def score(text):
    if not text:
        return 0.0
    length = len(text)
    printable = sum(c in string.printable for c in text)
    letters = sum(c.isalpha() for c in text)
    spaces = text.count(" ")
    newlines = text.count("\n")
    weird = text.count("�")
    printable_ratio = printable / length
    letter_ratio = letters / length
    space_ratio = spaces / length
    score = 0.0
    score += printable_ratio * 1.0
    score += letter_ratio * 0.5
    score += space_ratio * 0.3
    score += newlines * 0.01
    score -= weird * 0.5
    lowered = text.lower()
    return score


def try_format(source_fmt,data):
    try:
        decoded = convert_str(source_fmt, "text", data)
    except Exception:
        return None

    s = decoded
    sc = score(s)
    return Candidate(source_fmt=source_fmt, decoded_text=s, score=sc)

def detect_encodings(
    data: str,
    max_results: int = 5,
    try_rot: bool = True,
) -> List[Candidate]:
    candidates: List[Candidate] = []
    cand_text = Candidate(
        source_fmt="text(raw)",
        decoded_text=data,
        score=score(data),
    )
    candidates.append(cand_text)
    if hex(data):
        c = try_format("hex", data)
        if c:
            candidates.append(c)
    if b64(data):
        c = try_format("base64", data)
        if c:
            candidates.append(c)
    if b32(data):
        c = try_format("base32", data)
        if c:
            candidates.append(c)
    if bin(data):
        c = try_format("bin", data)
        if c:
            candidates.append(c)
    if url(data):
        c = try_format("url", data)
        if c:
            candidates.append(c)
    if try_rot and rot(data):
        best_rot_candidates: List[Candidate] = []
        for shift in range(1, 26):
            try:
                decoded = convert_str("rot", "text", data, rot_n=shift)
            except Exception:
                continue
            sc = score(decoded)
            best_rot_candidates.append(
                Candidate(
                    source_fmt="rot",
                    decoded_text=decoded,
                    score=sc,
                    extra_info=f"ROT={shift}",
                )
            )
        best_rot_candidates.sort(key=lambda c: c.score, reverse=True)
        candidates.extend(best_rot_candidates[:3])
    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates[:max_results]

if __name__ == "__main__":
    DATA = "ZmxhZ3t0ZXN0fQ=="
    MAX_RESULTS = 5
    TRY_ROT = True
    detected = detect_encodings(DATA, max_results=MAX_RESULTS, try_rot=TRY_ROT)
    print(f"Chaîne d'entrée : {DATA!r}\n")
    for i, cand in enumerate(detected, 1):
        extra = f" ({cand.extra_info})" if cand.extra_info else ""
        print(f"[{i}] format supposé : {cand.source_fmt}{extra}")
        print(f"    score : {cand.score:.3f}")
        print(f"    texte : {cand.decoded_text!r}")
        print()
