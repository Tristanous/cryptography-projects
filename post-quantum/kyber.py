"""
Implémentation simplifiée d’un KEM de type CRYSTALS-Kyber.

Objectif :
    Illustrer les idées principales de Kyber (polynômes, matrice A, bruit, encaps/decaps).

Résumé :
    - On travaille dans l’anneau R = Z_q[X] / (X^N + 1) avec :
        N = 256
        Q = 3329
        K = 2     (paramètre Kyber-512)
    - On manipule des vecteurs/matrices de polynômes modulo Q et X^N + 1.

Composants :
    - class Polynomial:
        Représente un polynôme de degré < N avec coefficients modulo Q.
        Opérations supportées :
            - addition, soustraction
            - multiplication naïve O(N^2) + réduction X^N ≡ -1
            - compression / décompression des coefficients
            - conversion en bytes

    - cbd(buffer, eta):
        Génère un polynôme de bruit selon une distribution binomiale centrée
        (version simplifiée pour l’exemple).

    - parse(stream):
        Simule la génération de la matrice publique A (K x K) à partir d’un flux
        pseudo-aléatoire

    - class KyberImplementation:
        .keygen():
            - Génère une graine aléatoire.
            - Dérive rho et sigma avec SHAKE-256.
            - Construit la matrice A à partir de rho.
            - Génère les vecteurs secrets s et e via cbd.
            - Calcule t = A * s + e.
            - Renvoie :
                public_key = (t, rho)
                secret_key = s

        .encaps(public_key):
            - Régénère A à partir de rho.
            - Génère de nouveaux bruits r, e1, e2.
            - Calcule u = A^T * r + e1.
            - Génère une graine mu_raw pour le secret partagé.
            - Encode mu_raw dans un polynôme binaire mu_poly (coeffs 0 ou Q/2).
            - Calcule v = t * r + e2 + mu_poly.
            - Compresse u et v pour former le ciphertext.
            - Dérive le secret partagé shared_secret = KDF(mu_raw).
            - Renvoie (ciphertext, shared_secret).

        .decaps(ciphertext, secret_key):
            - Décompresse u et v.
            - Calcule noisy_mu ≈ mu_poly + bruit via v - s * u.
            - Ré-extrait les bits de mu en comparant les coeffs à 0 et Q/2.
            - Reconstitue mu_raw à partir des bits.
            - Re-dérive le même secret partagé via KDF(mu_raw).

Limites :
    - Multiplication de polynômes naïve O(N^2) au lieu d’une NTT.
    - Sampling, compression, parsing, encodage du message : tout est simplifié.

Utilisation rapide :
    kyber = KyberImplementation()
    pk, sk = kyber.keygen()
    cipher, ss_alice = kyber.encaps(pk)
    ss_bob = kyber.decaps(cipher, sk)
    print(ss_alice == ss_bob)  # Doit être True si tout va bien.
"""
import os
import hashlib


N = 256
Q = 3329
K = 2
ETA = 2  # Paramètre pour la distribution du bruit (CBD)

class Polynomial:
    def __init__(self, coeffs=None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            self.coeffs = coeffs
            # Reduction modulo X^N + 1
            self.reduce()

    def reduce(self):
        """Applique modulo Q et modulo X^N + 1"""
        # Simplification: on suppose ici que l'entrée ne dépasse pas 2*N
        # Dans une implémentation NTT réelle, c'est différent.
        for i in range(len(self.coeffs)):
            self.coeffs[i] %= Q
        while len(self.coeffs) > N:
            val = self.coeffs.pop()
            idx = len(self.coeffs) - N
            self.coeffs[idx] = (self.coeffs[idx] - val) % Q

    def __add__(self, other):
        new_coeffs = [(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(new_coeffs)

    def __sub__(self, other):
        new_coeffs = [(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(new_coeffs)

    def __mul__(self, other):
        # Multiplication naïve O(N^2).
        # En réalité, on utilise la NTT (Number Theoretic Transform) pour O(N log N)
        res = [0] * (2 * N)
        for i in range(N):
            for j in range(N):
                res[i + j] = (res[i + j] + self.coeffs[i] * other.coeffs[j])
        
        # Reduction X^N = -1 mod Q
        # ex: x^256 -> -1, x^257 -> -x
        final = [0] * N
        for i in range(2 * N):
            if i < N:
                final[i] = (final[i] + res[i]) % Q
            else:
                final[i - N] = (final[i - N] - res[i]) % Q
        return Polynomial(final)

    def compress(self, d):
        """Compression des coefficients (perte d'information contrôlée)"""
        factor = (2**d) / Q
        new_coeffs = [int(round(c * factor)) % (2**d) for c in self.coeffs]
        return new_coeffs

    @staticmethod
    def decompress(compressed_coeffs, d):
        factor = Q / (2**d)
        new_coeffs = [int(round(c * factor)) for c in compressed_coeffs]
        return Polynomial(new_coeffs)

    def to_bytes(self):
        b = bytearray()
        for c in self.coeffs:
            b.extend(c.to_bytes(2, 'big'))
        return bytes(b)

def cbd(buffer, eta):
    """Centered Binomial Distribution: génère du bruit déterministe"""
    # Convertit des octets aléatoires en coefficients de polynôme petits
    # Implémentation simplifiée
    coeffs = [0] * N
    bits = int.from_bytes(buffer, 'big')
    for i in range(N):
        a = sum((bits >> (2*i*eta + j)) & 1 for j in range(eta))
        b = sum((bits >> (2*i*eta + eta + j)) & 1 for j in range(eta))
        coeffs[i] = (a - b) % Q
    return Polynomial(coeffs)

def parse(stream):
    """Transforme le flux XOF en une matrice A (Uniform Sampling)"""
    # Simulation: retourne une matrice KxK de polynômes aléatoires
    matrix = []
    for _ in range(K):
        row = []
        for _ in range(K):
            # Génération simulée pour l'exemple
            coeffs = [int(x) % Q for x in stream[:N]] 
            row.append(Polynomial(coeffs))
            stream = stream[N:] # shift
        matrix.append(row)
    return matrix


class KyberImplementation:
    def keygen(self):
        """Génération de clés (Public Key, Secret Key)"""
        #Graine aléatoire
        seed = os.urandom(32)
        
        #Expansion de la graine
        # On dérive rho (pour A) et sigma (pour le bruit s et e)
        h = hashlib.shake_256(seed)
        rho = h.digest(1024) # Simulation taille
        sigma = h.digest(1024)
        
        #Génération de la matrice A (Public)  
        A = parse(rho) # Matrice K x K
        
        #Génération des vecteurs secrets s et erreur e (Bruit)
        # s et e sont tirés de la distribution binomiale centrée
        s = [cbd(os.urandom(128), ETA) for _ in range(K)]
        e = [cbd(os.urandom(128), ETA) for _ in range(K)]
        
        #Calcul de t = A * s + e
        t = []
        for i in range(K):
            # Produit scalaire de la ligne i de A avec s
            acc = Polynomial()
            for j in range(K):
                acc = acc + (A[i][j] * s[j])
            # Ajout de l'erreur
            t.append(acc + e[i])
            
        public_key = (t, rho) # t est le vecteur public, rho régénère A
        secret_key = s        # s est le vecteur secret
        return public_key, secret_key

    def encaps(self, public_key):
        """Encapsulation: Crée un secret partagé et un chiffré"""
        t, rho = public_key
        A = parse(rho) # Régénération de A
        
        #Nouveau bruit pour l'encapsulation
        r = [cbd(os.urandom(128), ETA) for _ in range(K)]
        e1 = [cbd(os.urandom(128), ETA) for _ in range(K)]
        e2 = cbd(os.urandom(128), ETA)
        
        #Calcul du vecteur u = A_transpose * r + e1
        u = []
        for i in range(K):
            acc = Polynomial()
            for j in range(K):
                # A_transpose[i][j] = A[j][i]
                acc = acc + (A[j][i] * r[j])
            u.append(acc + e1[i])
            
        #Calcul du polynôme v = t * r + e2 + message_encodé
        # Ici le message est la graine du secret partagé
        mu_raw = os.urandom(32) #seed
        
        # Conversion des bits de mu en coefficients (0 ou Q/2)
        mu_poly = Polynomial()
        mu_bits = int.from_bytes(mu_raw, 'big')
        for i in range(256):
             if (mu_bits >> i) & 1:
                 mu_poly.coeffs[i] = int(Q / 2)
        
        # v = t_transpose * r + e2 + mu
        v_acc = Polynomial()
        for i in range(K):
            v_acc = v_acc + (t[i] * r[i])
        v = v_acc + e2 + mu_poly
        
        #Compression (Ciphertext)
        # On compresse u et v pour réduire la taille
        c_u = [poly.compress(10) for poly in u]
        c_v = v.compress(4)
        ciphertext = (c_u, c_v)
        
        #Dérivation du secret (KDF sur mu)
        shared_secret = hashlib.sha3_256(mu_raw).digest()
        
        return ciphertext, shared_secret

    def decaps(self, ciphertext, secret_key):
        """Décapsulation: Récupère le secret partagé"""
        c_u, c_v = ciphertext
        s = secret_key
        
        #Décompression
        u = [Polynomial.decompress(poly, 10) for poly in c_u]
        v = Polynomial.decompress(c_v, 4)
        
        #Calcul pour retirer le masque : noisy_mu = v - s * u
        #v - s*u ≈ (t*r + e2 + mu) - s*(A^T*r + e1)
        # Comme t = As+e, les termes s'annulent approximativement, laissant mu + bruit
        mask_acc = Polynomial()
        for i in range(K):
            mask_acc = mask_acc + (s[i] * u[i])
            
        noisy_mu = v - mask_acc
        
        #Récupération du message (arrondi vers 0 ou Q/2)
        recovered_bytes = bytearray(32)
        current_byte = 0
        bit_idx = 0
        
        for coeff in noisy_mu.coeffs:
            # Si le coeff est proche de Q/2, c'est un 1. Sinon 0.
            # Distance à Q/2 vs distance à 0
            dist_0 = min(coeff, Q - coeff)
            dist_half = abs(coeff - (Q // 2))
            
            if dist_half < dist_0:
                current_byte |= (1 << bit_idx)
            
            bit_idx += 1
            if bit_idx == 8:
                recovered_bytes[len(recovered_bytes) - (len(recovered_bytes))] = current_byte
                pass 
                
        # Reconstruction correcte du bytearray pour l'exemple
        rec_int = 0
        for i, coeff in enumerate(noisy_mu.coeffs):
             dist_half = abs(coeff - (Q // 2))
             dist_0 = min(coeff, Q - coeff)
             if dist_half < dist_0:
                 rec_int |= (1 << i)
        
        mu_raw = rec_int.to_bytes(32, 'big')
        
        #KDF pour retrouver le secret 
        shared_secret = hashlib.sha3_256(mu_raw).digest()
        
        return shared_secret

#Test

kyber = KyberImplementation()

pk, sk = kyber.keygen()

cipher, ss_alice = kyber.encaps(pk)

ss_bob = kyber.decaps(cipher, sk)

print("-" * 20)
print(f"{ss_alice.hex()[:16]}")
print(f"{ss_bob.hex()[:16]}")
print(f"{ss_alice == ss_bob}")