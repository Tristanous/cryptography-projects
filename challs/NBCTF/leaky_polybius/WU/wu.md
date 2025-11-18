# [Cryptanalyse] leaky_polybius - Write-Up

Ce challenge présente un service de chiffrement basé sur un carré de Polybe avec un alphabet secret. La vulnérabilité est un **oracle** : le service nous donne un "score" indiquant le nombre de lettres correctement placées lorsque l'on essaie de deviner l'alphabet.

-----

###  1 : Reconstruction de l'Alphabet

L'attaque consiste à deviner la position de chaque lettre, une par une. On envoie une proposition contenant uniquement la lettre que l'on cherche (par exemple `A`) et des caractères neutres (`.`). Si le score augmente de 1 par rapport à un alphabet de base ne contenant que des `.`, on a trouvé la bonne position. On "verrouille" cette lettre et on passe à la suivante.

Cette logique est implémentée dans la boucle principale du script :

```python
# Initialisation d'un alphabet vide et d'un score de base
secret_alphabet = list('.' * 25)
base_score = get_score('.' * 25)

# Boucle sur chaque lettre à trouver
for char_to_find in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
    # Boucle sur chaque position possible
    for i in range(25):
        # On ne teste que les cases vides
        if secret_alphabet[i] == '.':
            # On construit la proposition de test
            current_try_list = list(secret_alphabet)
            current_try_list[i] = char_to_find
            
            # Si le score augmente de 1, c'est la bonne position
            if get_score("".join(current_try_list)) == base_score + 1:
                secret_alphabet[i] = char_to_find # On valide la lettre
                base_score += 1                  # On met à jour le score de référence
                break                            # On passe à la lettre suivante
                
secret_alphabet_str = "".join(secret_alphabet)
```

-----

###  2 : Déchiffrement

Une fois l'alphabet secret entièrement reconstitué, on l'utilise pour déchiffrer le message initial. La fonction `decrypt_polybius` transforme l'alphabet en une grille de coordonnées 5x5 et traduit chaque paire de chiffres du message chiffré en la lettre correspondante.

```python
def decrypt_polybius(ciphertext, alphabet):
    grille = {}
    # Crée un dictionnaire de coordonnées, ex: {'11': 'A', '12': 'B', ...}
    for index, char in enumerate(alphabet):
        grille[f"{(index // 5) + 1}{(index % 5) + 1}"] = char
    
    plaintext = ""
    # Lit le message chiffré 2 par 2 et traduit
    for i in range(0, len(ciphertext), 2):
        plaintext += grille.get(ciphertext[i:i+2], '?')
    return plaintext

# Appel de la fonction avec les données récupérées
decrypted_password = decrypt_polybius(encrypted_message, secret_alphabet_str)
```

-----


**L'implémentation complète de la solution est disponible dans le fichier `solve.py`.**