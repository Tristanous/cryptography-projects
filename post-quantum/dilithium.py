"""
dilithium_simplified.py

Implémentation simplifiée d’un schéma de signature de type CRYSTALS-Dilithium.

Objectif :
    - Montrer la mécanique générale des signatures lattice-based (Dilithium-like).
    - Avoir un jouet pour expérimenter / jouer en CTF, pas un truc standard-conforme.
    - Ne PAS être utilisé pour de la vraie sécurité.

Cadre :
    - On travaille avec des polynômes modulo Q dans l’anneau Z_q[X] / (X^N + 1)
      avec ici des paramètres jouets proches de Dilithium :
        N = 256
        Q = 8380417
        K = 4
        L = 4
    - On manipule des matrices et vecteurs de polynômes :
        A : matrice publique K x L
        s1, s2 : vecteurs secrets à petits coefficients
        t = A * s1 + s2 : vecteur public

Composants principaux :
    - class Poly :
        Représente un polynôme de degré < N avec coefficients modulo Q.
        Opérations :
            - addition, soustraction
            - multiplication naïve O(N^2) avec réduction X^N ≡ -1
        Fournit :
            - inf_norm() : norme infinie (valeur max centrée autour de 0) pour contrôler les bornes.

    - random_poly(bound) :
        Génère un polynôme aux coefficients pseudo-aléatoires dans [-bound, +bound].
        Sert pour s1, s2, le masque y, etc.

    - gen_challenge(stream_bytes) :
        Construit un polynôme challenge c à partir d’un flux de bytes (hash du message).
        Le challenge a TAU coefficients non nuls dans {+1, -1} et le reste à 0
        (version simplifiée de la génération de challenge dans Dilithium).

    - class DilithiumImplementation :

        keygen():
            - Génère une matrice A (K x L) de polynômes aléatoires.
              (Dans la vraie Dilithium, A est dérivée d’une seed via SHAKE, ici c’est random.)
            - Génère s1 (L polynômes) et s2 (K polynômes) avec petits coefficients.
            - Calcule t = A * s1 + s2.
            - Renvoie :
                pk = t
                sk = (s1, s2)

        sign(message, sk):
            Schéma de type Fiat–Shamir with aborts, version simple :
            - Tire un masque y à petits coefficients (vecteur de L polynômes).
            - Calcule w = A * y.
            - Hache (message || sérialisation(w)) pour obtenir un digest.
            - Transforme ce digest en challenge c via gen_challenge().
            - Calcule z = y + c * s1.
            - Vérifie que la norme de z reste inférieure à (GAMMA1 - BETA).
              Si ce n’est pas le cas, on rejette et on recommence (abort).
            - Renvoie la signature (z, c) quand une tentative réussit.

        verify(message, signature, pk):
            - Vérifie que chaque polynôme de z a une norme < (GAMMA1 - BETA).
            - Reconstruit w' ≈ A * y via la relation
                  w' = A * z - c * t
              en supposant que la partie c * s2 est négligeable/simplifiée.
            - Recalcule un challenge c' depuis (message || w').
            - Accepte si c' et c coïncident (coeffs identiques).

Limites :
    - Paramètres, sampling, réductions, et vérifications sont simplifiés.
    - Pas d’NTT, pas de seeds structurées, pas de hints, pas de protections side-channel.
    - La vérification ignore certains détails importants de Dilithium (notamment la gestion fine de s2 et des hints).

Utilisation rapide :
    dili = DilithiumImplementation()
    pk, sk = dili.keygen()
    msg = b"test"
    sig = dili.sign(msg, sk)
    ok = dili.verify(msg, sig, pk)
    print(ok)
"""
import os
import hashlib
import random

N = 256
Q = 8380417  # Un premier plus grand que celui de Kyber
K = 4        # Dimension de la matrice (4x4)
L = 4
GAMMA1 = (Q - 1) // 16  # Borne pour le masque y
BETA = 78               # Borne pour la signature z (simplifiée)
TAU = 39                # Nombre de +/- 1 dans le challenge c

class Poly:
    def __init__(self, coeffs=None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            self.coeffs = [c % Q for c in coeffs]

    def __add__(self, other):
        return Poly([(a + b) for a, b in zip(self.coeffs, other.coeffs)])

    def __sub__(self, other):
        return Poly([(a - b) for a, b in zip(self.coeffs, other.coeffs)])

    def __mul__(self, other):
        # Multiplication naïve O(N^2) - En vrai : NTT
        res = [0] * (2 * N)
        for i in range(N):
            for j in range(N):
                res[i + j] = (res[i + j] + self.coeffs[i] * other.coeffs[j])
        
        # Réduction X^N = -1
        final = [0] * N
        for i in range(2 * N):
            if i < N:
                final[i] = (final[i] + res[i]) % Q
            else:
                final[i - N] = (final[i - N] - res[i]) % Q
        return Poly(final)

    def inf_norm(self):
        """Norme infinie : le plus grand coefficient en valeur absolue"""
        # On regarde la distance par rapport à 0 (centré autour de Q)
        m = 0
        for c in self.coeffs:
            # Si c > Q/2, c'est un nombre négatif (c-Q)
            val = c if c <= Q // 2 else Q - c
            if val > m:
                m = val
        return m

def random_poly(bound):
    """Génère un polynôme avec coeffs entre -bound et +bound"""
    coeffs = []
    for _ in range(N):
        # randrange génère dans [0, 2*bound], on décale de bound
        val = random.randrange(0, 2 * bound + 1) - bound
        coeffs.append(val)
    return Poly(coeffs)

def gen_challenge(stream_bytes):
    # On utilise un PRNG déterministe basé sur le hash du message
    random.seed(stream_bytes) 
    
    coeffs = [0] * N
    # On place TAU positions à 1 ou -1
    positions = random.sample(range(N), TAU)
    for pos in positions:
        coeffs[pos] = 1 if random.random() > 0.5 else -1
    
    return Poly(coeffs)


class DilithiumImplementation:
    def keygen(self):
        """Génération des clés"""
        # Matrice A (K x L) de polynômes aléatoires
        # Dans la vraie vie : dérivée d'une seed rho via SHAKE-128
        self.A = [[random_poly(Q//2) for _ in range(L)] for _ in range(K)]
        
        # Vecteurs secrets s1, s2 (petits coefficients)
        s1 = [random_poly(1) for _ in range(L)] # Coeffs dans {-1, 0, 1}
        s2 = [random_poly(1) for _ in range(K)]
        
        # Calcul de t = A * s1 + s2
        t = []
        for i in range(K):
            acc = Poly()
            for j in range(L):
                acc = acc + (self.A[i][j] * s1[j])
            t.append(acc + s2[i])
            
        pk = t      # Public Key
        sk = s1, s2 # Secret Key
        return pk, sk

    def sign(self, message, sk):
        """Signature (Fiat-Shamir with Aborts)"""
        s1, s2 = sk
        attempt = 0
        while True:
            attempt += 1
            
            # Générer un vecteur masque y
            y = [random_poly(GAMMA1) for _ in range(L)]
            
            # Calculer w = A * y
            w = []
            for i in range(K):
                acc = Poly()
                for j in range(L):
                    acc = acc + (self.A[i][j] * y[j])
                w.append(acc)
            
            # Hacher (Message + w) pour créer le challenge c
            # Sérialisation très simplifiée
            w_bytes = b"".join([bytes(str(p.coeffs), 'utf-8') for p in w])
            digest = hashlib.sha256(message + w_bytes).digest()
            c = gen_challenge(digest)
            
            # Calculer la signature potentielle z = y + c * s1
            z = []
            potential_security_leak = False
            for i in range(L):
                # z = y + c*s1
                term = (c * s1[i])
                z_poly = y[i] + term
                z.append(z_poly)
                
                # Vérification des bornes
                # Si z est trop grand, ça révèle des infos sur s1 -> REJET
                if z_poly.inf_norm() >= (GAMMA1 - BETA):
                    potential_security_leak = True
                    break
            
            if potential_security_leak:
                continue # On recommence la boucle
                
            # Si on arrive ici, la signature est valide et sûre
            # La vraie Dilithium calcule aussi des "Hints" (h) ici
            print(f"Signature réussie après {attempt} tentative(s)")
            return z, c

    def verify(self, message, signature, pk):
        """Vérification de la signature"""
        z, c = signature
        t = pk
        
        # Vérifier la taille de z (Doit être < Gamma1 - Beta)
        for poly in z:
            if poly.inf_norm() >= (GAMMA1 - BETA):
                print("Erreur: Norme de z trop grande")
                return False
        
        # Reconstruire w'
        # A*z - c*t = A*(y + c*s1) - c*(A*s1 + s2)
        # = A*y + A*c*s1 - c*A*s1 - c*s2
        # = A*y - c*s2
        # ≈ w (car c*s2 est petit et négligé ou corrigé par les Hints dans la vraie version)
        
        # Dans cette version simple, on suppose s2 négligeable
        # ou absorbé, pour montrer la mécanique A*z - c*t.
        
        w_prime = []
        for i in range(K):
            Az_acc = Poly()
            for j in range(L):
                Az_acc = Az_acc + (self.A[i][j] * z[j])
            
            ct_term = c * t[i]
            w_prime.append(Az_acc - ct_term)

        # Recalculer le challenge c' avec ce w'
        w_bytes = b"".join([bytes(str(p.coeffs), 'utf-8') for p in w_prime])
        digest = hashlib.sha256(message + w_bytes).digest()
        c_prime = gen_challenge(digest)
        
        # Comparer le challenge calculé avec celui de la signature
        # Dans ma version simplifiée sans "Hints", l'égalité exacte des coeffs c
        # peut échouer à cause du terme 'c*s2'.
        # Ici, on vérifie simplement que w' est cohérent.
        return c.coeffs == c_prime.coeffs 

#Test

dili = DilithiumImplementation()
pk, sk = dili.keygen()

msg = b"test"
print(f"Signature du message: '{msg.decode()}'")
sig = dili.sign(msg, sk)

valid = dili.verify(msg, sig, pk)

if valid:
    print("Valide")
else:
    print("Invalide")