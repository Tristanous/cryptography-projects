"""
Implémentation simplifiée de WOTS et d’un SPHINCS.

Objectif :
    - Montrer les idées de base des signatures hash-based post-quantiques :
        * WOTS (Winternitz One-Time Signature)
        * Arbre de Merkle pour obtenir une clé publique compacte

Paramètres jouets :
    N   = 16 octets (128 bits de sortie de hash pour l’exemple)
    W   = 16 (base Winternitz, donc 4 bits par “digit”)
    LOG_W = 4
    h   = hauteur de l’arbre de Merkle (par défaut 3 => 8 feuilles)

Fonctions / classes :

    hash_f(data)
        SHA-256 tronqué à N octets. C’est la primitive de base.

    class WOTS
        Implémentation d’un schéma Winternitz One-Time Signature simplifié.

        Idée :
            - La clé secrète SK = liste de L blocs aléatoires.
            - La clé publique PK = chaque bloc SK[i] haché (W-1) fois.
            - Pour signer, on part de SK[i] et on hache un nombre de fois
              dépendant du message (en base W).
            - Pour vérifier, on “complète” la chaîne de hash jusqu’à W-1 et
              on doit retomber sur la PK.

        Détails :
            - len_1 : nombre de “digits” en base W pour représenter le message haché.
            - len_2 : longueur du checksum.
            - L = len_1 + len_2 : nombre total de blocs WOTS.

        Méthodes :
            base_w(msg) :
                Convertit msg (N octets) en une liste de valeurs dans [0, W-1].

            checksum(msg_base_w) :
                Ajoute un checksum pour éviter certaines attaques de raccourci.

            chain(val, start_index, steps) :
                Applique hash_f en chaîne “steps” fois (chaîne de Winternitz).

            keygen() -> (sk, pk, pk_compressed) :
                - sk : liste de L blocs aléatoires.
                - pk : liste de L blocs = hash_f appliqué (W-1) fois à chaque sk[i].
                - pk_compressed : hash_f de la concaténation de pk (feuille Merkle).

            sign(msg, sk) -> sig :
                - Convertit msg en base W, puis ajoute le checksum.
                - Pour chaque index i, applique chain(sk[i], 0, steps_i).
                - sig : liste de blocs, un par élément de la représentation base W + checksum.

            verify_from_sig(msg, sig) -> pk_candidate :
                - Re-fait base_w(msg) + checksum.
                - Complète chaque chaîne de signature jusqu’à W-1.
                - Concatène le tout et hash_f pour reconstruire une PK compressée candidate.

    class SPHINCS_Simple
        Version ultra simplifiée d’un schéma à la SPHINCS :
        - Un seul arbre de Merkle,
        - Chaque feuille = une clé publique WOTS compressée,
        - La signature = (signature WOTS de msg_hash, chemin d’authentification Merkle).

        Paramètres :
            h : hauteur de l’arbre (num_leaves = 2^h).

        keygen() -> pub_root :
            - Génère num_leaves paires de clés WOTS.
            - Construit l’arbre de Merkle sur les pk_compressed de WOTS.
            - Stocke :
                * self.tree : l’arbre binaire
                * self.wots_keys : les clés WOTS pour les feuilles
            - pub_root = racine de l’arbre (clé publique globale).

        get_auth_path(leaf_idx) :
            - Pour une feuille donnée, récupère les noeuds frères nécessaires
              pour reconstituer la racine (chemin d’authentification Merkle).

        sign(msg) -> signature :
            - Choisit une feuille à partir de msg (ici : index = msg[:4] mod num_leaves).
            - Signe msg avec la clé WOTS correspondante.
            - Récupère le chemin d’authentification Merkle.
            - Renvoie :
                {
                    'leaf_idx': index de la feuille,
                    'wots_sig': signature WOTS,
                    'auth_path': chemin Merkle
                }

        verify(msg, sig, pub_root) -> bool :
            - Reconstitue la PK WOTS compressée à partir de (msg, wots_sig).
            - Remonte l’arbre de Merkle en utilisant auth_path et leaf_idx.
            - Vérifie que la racine reconstituée == pub_root.

Limites :
    - Paramètres trop petits, hash tronqué, génération de feuilles naïve.
    - Pas de seeds, pas de PRF, pas de FORS, pas d’HyperTree comme dans SPHINCS+ réel.


Utilisation rapide :
    sp = SPHINCS_Simple(height=3)
    pk = sp.keygen()
    msg = b"Test"
    msg_hash = hash_f(msg)
    sig = sp.sign(msg_hash)
    ok = sp.verify(msg_hash, sig, pk)
    print(ok)
"""
import hashlib
import math
import os

#Paramètres Simplifiés
# En vrai: N=32 (256 bits), W=16
N = 16     # Taille du hash en octets (128 bits pour cet exemple)
W = 16     # Paramètre de Winternitz (base 16 pour la chaîne)
LOG_W = 4  # log2(W)

def hash_f(data):
    """Fonction de hachage standard (SHA-256 tronqué à N)"""
    h = hashlib.sha256(data).digest()
    return h[:N]

class WOTS:
    """
    Winternitz One-Time Signature.
    On signe en hachant X fois une valeur secrète.
    """
    def __init__(self):
        # Calcul de len_1 : combien de blocs de LOG_W bits pour coder le message 
        # Pour N octets, on a N*8 bits. Divisé par log2(W).
        self.len_1 = math.ceil((N * 8) / LOG_W)
        # len_2 : checksum
        self.len_2 = math.floor(math.log2(self.len_1 * (W - 1)) / LOG_W) + 1
        self.L = self.len_1 + self.len_2

    def chain(self, val, start_index, steps):
        """La chaîne de hachage: Hash(Hash(...Hash(val)...))"""
        curr = val
        for i in range(start_index, start_index + steps):
            curr = hash_f(curr)
        return curr

    def keygen(self):
        """Génère une paire de clés WOTS"""
        # SK: L valeurs aléatoires
        sk = [os.urandom(N) for _ in range(self.L)]
        # PK: On hache chaque valeur du SK (W-1) fois
        pk = [self.chain(sk[i], 0, W - 1) for i in range(self.L)]
        # On compresse la PK en un seul hash pour l'arbre de Merkle
        pk_compressed = hash_f(b"".join(pk))
        return sk, pk, pk_compressed

    def base_w(self, msg):
        """Convertit le message en une liste d'entiers [0, W-1]"""
        # Simplification: on suppose que msg fait N octets
        val = int.from_bytes(msg, 'big')
        output = []
        for _ in range(self.len_1):
            output.append(val % W)
            val //= W
        return output[::-1]

    def checksum(self, msg_base_w):
        """Calcule le checksum nécessaire à la sécurité WOTS"""
        csum = 0
        for val in msg_base_w:
            csum += (W - 1 - val)
        # Conversion du csum en base W
        csum_base_w = []
        for _ in range(self.len_2):
            csum_base_w.append(csum % W)
            csum //= W
        return csum_base_w[::-1]

    def sign(self, msg, sk):
        """Signe un message"""
        # Conversion message -> base W
        lengths = self.base_w(msg)
        # Ajout du checksum
        lengths += self.checksum(lengths)
        # Signature: On hache chaque sk[i] selon la valeur du message
        # Si le message dit "5", on hache sk 5 fois.
        sig = []
        for i, steps in enumerate(lengths):
            sig.append(self.chain(sk[i], 0, steps))
        return sig

    def verify_from_sig(self, msg, sig):
        """Reconstruit la PK candidate à partir de la signature"""
        lengths = self.base_w(msg)
        lengths += self.checksum(lengths)
        # On finit la chaîne: si on a haché 5 fois, on hache encore (W-1)-5 fois
        # pour espérer retomber sur la PK.
        reconstructed_pk_parts = []
        for i, steps in enumerate(lengths):
            missing_steps = (W - 1) - steps
            reconstructed_pk_parts.append(self.chain(sig[i], steps, missing_steps))
        return hash_f(b"".join(reconstructed_pk_parts))


class SPHINCS_Simple:
    """
    Version simplifiée: Un seul arbre de Merkle.
    SPHINCS+ réel utilise un "HyperTree" et FORS.
    """
    def __init__(self, height=3):
        self.h = height
        self.num_leaves = 1 << height # 2^h feuilles
        self.wots = WOTS()
        self.tree = [None] * (2 * self.num_leaves) # Stockage de l'arbre binaire
        self.wots_keys = [] # Stockage temporaire des clés (pour l'exemple)

    def keygen(self):
        print(f"Génération de {self.num_leaves} clés WOTS+")
        # Générer toutes les feuilles (WOTS PK compressées)
        for i in range(self.num_leaves):
            sk, pk_full, pk_comp = self.wots.keygen()
            # On stocke tout pour la démo
            self.wots_keys.append({'sk': sk, 'pk': pk_full}) 
            # Les feuilles sont placées à la fin du tableau tree
            self.tree[self.num_leaves + i] = pk_comp

        # Construire l'arbre de Merkle (Hash des fils)
        for i in range(self.num_leaves - 1, 0, -1):
            left = self.tree[2 * i]
            right = self.tree[2 * i + 1]
            self.tree[i] = hash_f(left + right)
            
        self.pub_root = self.tree[1] # La racine est à l'index 1
        return self.pub_root

    def get_auth_path(self, leaf_idx):
        """Récupère les voisins nécessaires pour remonter à la racine"""
        path = []
        idx = leaf_idx + self.num_leaves
        while idx > 1:
            if idx % 2 == 0: # Fils gauche, besoin du droit
                path.append(self.tree[idx + 1])
            else: # Fils droit, besoin du gauche
                path.append(self.tree[idx - 1])
            idx //= 2
        return path

    def sign(self, msg):
        # Ici, on choisit une feuille au hasard pour signer.
        # SPHINCS+ utilise FORS pour choisir pseudo-aléatoirement.
        leaf_idx = int.from_bytes(msg[:4], 'big') % self.num_leaves
        
        wots_sk = self.wots_keys[leaf_idx]['sk']
        
        # Signature WOTS du message
        wots_sig = self.wots.sign(msg, wots_sk)
        
        # Chemin d'authentification Merkle
        auth_path = self.get_auth_path(leaf_idx)
        
        return {
            'leaf_idx': leaf_idx,
            'wots_sig': wots_sig,
            'auth_path': auth_path
        }

    def verify(self, msg, sig, pub_root):
        leaf_idx = sig['leaf_idx']
        wots_sig = sig['wots_sig']
        path = sig['auth_path']
        
        # Vérifier WOTS -> On obtient une feuille candidate
        reconstructed_leaf = self.wots.verify_from_sig(msg, wots_sig)
        
        # Remonter l'arbre de Merkle avec le chemin
        curr = reconstructed_leaf
        idx = leaf_idx + self.num_leaves
        
        for neighbor in path:
            if idx % 2 == 0: # On est à gauche
                curr = hash_f(curr + neighbor)
            else: # On est à droite
                curr = hash_f(neighbor + curr)
            idx //= 2
            
        # Comparer la racine calculée avec la clé publique
        return curr == pub_root

# Test

sp = SPHINCS_Simple(height=3) # Petit arbre de 8 feuilles
pk = sp.keygen()
print(f"Clé Publique : {pk.hex()}")

msg = b"Test"
# On hash le msg pour avoir la bonne taille
msg_hash = hash_f(msg) 

signature = sp.sign(msg_hash)
print(f"Index utilisé : {signature['leaf_idx']}")
print(f"Taille signature WOTS : {len(signature['wots_sig'])} blocs")
print(f"Taille chemin Merkle  : {len(signature['auth_path'])} noeuds")

is_valid = sp.verify(msg_hash, signature, pk)

if is_valid:
    print("Succes")
else:
    print("Echec")