# [Cryptanalyse] pivotal_moment - Write-Up

L'objectif de ce challenge était de reconstituer un polynôme secret pour en extraire une clé AES et un iv.

---
### 1. Le Problème 

L'énoncé nous fourni 11 points `(x, y)` et nous informe qu'ils appartiennent à un polynôme de degré 10. Un polynôme de degré 10 est défini par 11 coefficients uniques :
$$P(x) = a_{10}x^{10} + a_9x^9 + \dots + a_1x + a_0$$

Le but est de retrouver tous ces coefficients car on comprend en lisant le code que:
* Le coefficient **`a₀`** correspondait à la **clé AES**.
* Le coefficient **`a₁`** correspondait à l'**IV**.

Puisque nous avons 11 points pour 11 inconnues, nous pouvons modéliser le problème comme un système de 11 équations linéaires.

---
### 2. Résolution

#### **Mise en Équation**
Chaque point `(x, y)` donné fournit une équation. Par exemple, pour le point `(x₁, y₁)` :
$$a_{10}x_1^{10} + a_9x_1^9 + \dots + a_1x_1 + a_0 = y_1$$

En posant cela pour les 11 points, on obtient un système matriciel de la forme $M \cdot A = Y$, où `M` est une **matrice de Vandermonde** 11x11, `A` est le vecteur des coefficients que l'on cherche, et `Y` est le vecteur des ordonnées.


#### **Le Pivot de Gauss**
Pour résoudre ce système, on peut utiliser la méthode du **pivot de Gauss**. L'algorithme consiste à transformer la matrice `M` en la matrice identité par des opérations sur les lignes.


La difficulté était d’adapter cet algorithme à l’**arithmétique modulaire**. Chaque division $a/b$ devait être remplacée par une multiplication par l’**inverse modulaire** $a\cdot \mathrm{inv}(b,p)$. **C’est valable ici car on travaille dans le corps fini $\mathbb{F}_p$ avec $p=2^{128}+51$ (premier) : tout $b\not\equiv 0 \pmod p$ est inversible ( $\gcd(b,p)=1$ ), et, avec des $x_i$ deux à deux distincts mod $p$, les pivots de la Vandermonde sont non nuls donc inversibles.** Le script de solution implémente donc cette méthode pour retrouver le vecteur des coefficients $A$.

---
### 3. Dechiffrement 

Une fois le système résolu, le script récupère les deux premiers coefficients de la solution : `a₀` et `a₁`.

1.  **Extraction de la clé et de l'IV :** `a₀` (la clé) et `a₁` (l'IV) sont de très grands nombres. Comme une clé AES-128 et son IV font 16 octets (128 bits), il fallait les convertir en utilisant la fonction `int.to_bytes(16, 'big')`.
2.  **Déchiffrement :** Le flag chiffré fourni en hexadécimal est converti en octets. Il ne restait plus qu'à utiliser la lib de Crypto pour déchiffrer le message avec la clé et l'IV.
3.  **Unpadding :** L'algorithme AES chiffre par blocs. La dernière étape consiste à retirer le "padding" (des octets de remplissage).

Le script de solution est dispo dans le `solve.py`.

#### **Pour Aller Plus Loin : Les Polynômes de Lagrange**
Si ça vous intéresse, il existe une méthode plus directe pour ce genre de problème si l'on ne s'intéresse qu'à la valeur du polynôme en certains points. **L'interpolation de Lagrange** permet de reconstruire le polynôme et de l'évaluer.

La forme générale du polynôme de Lagrange est une somme pondérée des ordonnées $y_j$ :
$$P(x) = \sum_{j=1}^{11} y_j \cdot L_j(x)$$

Où les $L_j(x)$ sont les **polynômes de base de Lagrange**, définis par :
$$L_j(x) = \prod_{\substack{1 \le i \le 11 \\ i \neq j}} \frac{x - x_i}{x_j - x_i}$$
Chaque polynôme de base $L_j(x)$ a la particularité de valoir 1 en $x_j$ et 0 pour tous les autres points $x_i$.

